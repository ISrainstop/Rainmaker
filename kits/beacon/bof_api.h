/*
 * csdev :: bof_api.h  --  Beacon API 内部接口 (bof.c <-> bof_api.c)
 * ==========================================================================
 * 本头文件不是对外接口。bof.h 的 bof_execute 是唯一对外入口。
 *
 * 这里定义两类东西:
 *   1) Beacon API 符号查找 —— bof.c 解析 COFF 外部符号时调用
 *   2) 输出汇聚 (sink) —— bof_execute 在调用 go 之前安装, BeaconOutput /
 *      BeaconPrintf 把内容写进调用方提供的缓冲
 * ==========================================================================
 */
#ifndef CSDEV_BOF_API_H
#define CSDEV_BOF_API_H

/* 按名字查找 Beacon API。name 已剥掉 __imp_ / __imp__ 前缀与 @N 后缀。
 * 命中返回函数地址, 未命中返回 0。 */
void *bof_api_lookup(const char *name);

/* 解析 <MODULE>$<FUNC> 形式的 Windows API 符号 (模块名不带 .dll)。
 * 模块句柄内部缓存; 命中返回函数地址, 未命中返回 0。 */
void *bof_resolve_winapi(const char *mod, const char *func);

/* ------------------------------------------------------------ 输出汇聚 */
/* bof_execute 在调用 BOF 之前调用 begin, 之后调用 end 取回字节数。
 * 非重入: 同一时刻只允许一个 BOF 在执行 (与 beacon2.c 的任务串行模型一致)。 */
void         bof_sink_begin(char *buf, unsigned int cap);
unsigned int bof_sink_end(void);

/* BeaconOutput / BeaconPrintf 的底层写入口。返回本次实际写入的字节数。 */
unsigned int bof_sink_write(const char *data, unsigned int len);

#endif /* CSDEV_BOF_API_H */
