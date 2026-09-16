/*
 * csdev :: shotstream.h  --  连续截图流
 * ==========================================================================
 * 与单次 screenshot 的区别:
 *   进程内起一个后台线程按固定间隔抓屏并编码 JPEG, 主循环每轮取走"最新一张"
 *   交给 sink 发送。**只保留最新一张**: 截图流要的是"现在屏幕上是什么",
 *   而不是"不丢任何一帧" —— 发送慢的时候丢弃中间帧才是正确取舍。
 *
 * 前提: 依赖 jpeg.c 的 GDI+ 编码。没有 JPEG 时一张 BMP 是 4.4 MB, 这个功能
 *       在带宽上不成立 (见 jpeg.h 的说明)。
 * ==========================================================================
 */
#ifndef CSDEV_SHOTSTREAM_H
#define CSDEV_SHOTSTREAM_H

/* sink 语义: 接管 data 的所有权 (无论返回什么), 返回 0 = 已接手, 非 0 = 忙/丢弃 */
typedef int (*shot_sink_fn)(unsigned int job, unsigned char *data, unsigned int len);

/* 启动。interval_ms 下限 1000。成功返回 1。 */
int shotstream_start(unsigned int interval_ms, shot_sink_fn sink);

/* 停止并释放缓冲 */
void shotstream_stop(void);

/* 主循环每轮调用: 把最新一张交给 sink */
void shotstream_pump(void);

int shotstream_active(void);

#endif /* CSDEV_SHOTSTREAM_H */
