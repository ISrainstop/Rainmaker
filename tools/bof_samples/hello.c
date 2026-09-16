/*
 * csdev :: tools/bof_samples/hello.c  --  端到端验证用测试 BOF
 * ==========================================================================
 * 目的: 用最小的自定义 BOF 覆盖加载器的四条关键路径
 *   1) 外部符号解析 —— 全部 Beacon API 走 __declspec(dllimport), 生成
 *      __imp_BeaconXxx 未定义符号, 与真实 CS BOF 的符号形态一致
 *   2) REL32 重定位   —— 字符串字面量位于 .rdata, 通过 RIP 相对寻址引用
 *   3) 参数解析       —— BeaconDataParse / BeaconDataExtract / BeaconDataInt
 *   4) 输出回传       —— BeaconPrintf / BeaconOutput / BeaconFormat* 族
 *
 * 编译:
 *   gcc -O2 -c tools/bof_samples/hello.c -o build/bof_samples/hello.o
 *
 * 注意: 这里刻意不包含真实的 beacon.h, 而是内联最小声明。真实 BOF 用
 * <windows.h> + beacon.h 即可, 与加载器无关。
 * ==========================================================================
 */
#include <windows.h>

/* -------------------------------------------------- beacon.h 的最小复刻 */
/* 字段布局必须与 CS 提供的 beacon.h 完全一致: BOF 会把这个结构体声明在
 * 自己的栈上, 加载器若假设更大的结构就会踩坏调用方的栈。 */

typedef struct {
    char *original;   /* 原始缓冲 */
    char *buffer;     /* 当前读指针 */
    int   length;     /* 剩余可读长度 */
    int   size;       /* 原始总长度 */
} datap;

typedef struct {
    char *original;   /* 原始缓冲 */
    char *buffer;     /* 当前写指针 */
    int   length;     /* 已写入长度 */
    int   size;       /* 缓冲容量 */
} formatp;

#define CALLBACK_OUTPUT      0x00
#define CALLBACK_ERROR       0x0d
#define CALLBACK_OUTPUT_UTF8 0x20

/* 用 dllimport 声明 => 编译器生成 __imp_<name> 间接符号,
 * 与 CS BOF 的符号命名完全一致 (x64 上是单个下划线)。 */
__declspec(dllimport) void  BeaconDataParse(datap *parser, char *buffer, int size);
__declspec(dllimport) char *BeaconDataExtract(datap *parser, int *size);
__declspec(dllimport) int   BeaconDataInt(datap *parser);
__declspec(dllimport) short BeaconDataShort(datap *parser);
__declspec(dllimport) int   BeaconDataLength(datap *parser);

__declspec(dllimport) void  BeaconPrintf(int type, char *fmt, ...);
__declspec(dllimport) void  BeaconOutput(int type, char *data, int len);

__declspec(dllimport) void  BeaconFormatAlloc(formatp *format, int maxsz);
__declspec(dllimport) void  BeaconFormatReset(formatp *format);
__declspec(dllimport) void  BeaconFormatAppend(formatp *format, char *text, int len);
__declspec(dllimport) void  BeaconFormatPrintf(formatp *format, char *fmt, ...);
__declspec(dllimport) char *BeaconFormatToString(formatp *format, int *size);
__declspec(dllimport) void  BeaconFormatFree(formatp *format);
__declspec(dllimport) void  BeaconFormatInt(formatp *format, int value);

/* ================================================================== 入口 */
/* CS BOF 约定: 入口符号名 go, 签名 void go(char *args, int len)。
 * x64 上默认就是微软 ABI, 无需要额外的调用约定标注。 */

void go(char *args, int len)
{
    datap  parser;
    formatp fp;
    char  *msg;
    char  *buf;
    int    msg_len = 0;
    int    got_len = 0;
    int    num = 0;
    int    remain;

    BeaconPrintf(CALLBACK_OUTPUT, "[+] hello BOF: 入口已执行, 参数块 %d 字节\n", len);

    /* ---- 1) 解析参数 ---- */
    BeaconDataParse(&parser, args, len);

    msg = BeaconDataExtract(&parser, &msg_len);      /* [4B 长度][数据] */
    num = BeaconDataInt(&parser);                    /* 裸 4 字节整数     */
    remain = BeaconDataLength(&parser);              /* 剩余字节数        */

    if (msg) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] 参数1(字符串) = \"%s\" (%d 字节)\n",
                     msg, msg_len);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] 参数1 解析失败\n");
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[+] 参数2(整数)   = %d (0x%x)\n", num, num);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] 剩余未解析    = %d 字节\n", remain);

    /* ---- 2) 用 formatp 组装一段输出并回传 ---- */
    BeaconFormatAlloc(&fp, 512);
    BeaconFormatPrintf(&fp, "hello BOF ok | msg=%s | num=%d | rest=%d\n",
                       msg ? msg : "(null)", num, remain);
    BeaconFormatInt(&fp, num);                       /* 追加 4 字节, 大端 */
    buf = BeaconFormatToString(&fp, &got_len);
    if (buf && got_len > 0) {
        BeaconOutput(CALLBACK_OUTPUT, buf, got_len);
    }
    BeaconFormatFree(&fp);

    /* ---- 3) 走一遍 Reset 路径, 确认可复用 ---- */
    BeaconFormatAlloc(&fp, 64);
    BeaconFormatAppend(&fp, "reset-ok", 8);
    BeaconFormatReset(&fp);
    buf = BeaconFormatToString(&fp, &got_len);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] format reset 后长度 = %d\n", got_len);
    (void)buf;
    BeaconFormatFree(&fp);

    /* ---- 4) 触发一条 .rdata 的 RIP 相对引用 (REL32 重定位路径) ---- */
    BeaconPrintf(CALLBACK_OUTPUT_UTF8, "%s\n",
                 "hello BOF done");
}
