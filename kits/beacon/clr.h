/*
 * csdev :: clr.h  --  CLR hosting 接口 (execute-assembly 用)
 * ==========================================================================
 * 设计取舍 (重要, 决定部署方式时看这里):
 *   CLR hosting 的 ExecuteInDefaultAppDomain 只能调用
 *   `static int <Type>.<Method>(string)`。真实 .NET 工具的入口是
 *   `static void Main(string[])`, 因此引入一个受控的**引导程序集**
 *   (kits/packer/csdev_clr_stub.cs, 编译后约 5 KB) 来承接参数并在内存里
 *   Assembly.Load(byte[]) + 反射调用目标入口。
 *
 *   于是落地情况是:
 *     - 引导 stub: **会写临时文件** (它是通用代码, 不含目标程序集特征)
 *     - 目标程序集: **全程在内存** (base64 经参数传入 stub)
 *   这与"目标程序集不落地"的核心诉求一致; 若要求连 stub 也不落地,
 *   需要把 CLR 的 AppDomain vtable 全部手写展开, 收益有限而风险很高。
 *
 * 代价 (必须知道的副作用):
 *   CLR 一旦加载进当前进程就**无法真正卸载**, 该进程此后会长期带有
 *   clr.dll / mscorlib 等模块痕迹。对隐蔽性有要求时, 应当把 execute-assembly
 *   放进新进程执行 (CS 的 fork&run 就是为此)。当前实现是**进程内执行**。
 * ==========================================================================
 */
#ifndef CSDEV_CLR_H
#define CSDEV_CLR_H

/* 在进程内启动 CLR 并调用 stub 的入口。
 *   stubPath : 引导程序集路径 (csdev_clr_stub.dll)
 *   typeName : 类型全名, 如 "CsdevStub"
 *   method   : 静态方法名, 如 "Run"
 *   arg      : 传给 stub 的单字符串参数 (约定见 csdev_clr_stub.cs)
 *   retOut   : 接收 stub 返回值
 * 返回 0 成功; 非 0 为错误码 (见 clr.c 内的注释)。
 */
int clr_execute_in_dll(const char *stubPath, const char *typeName,
                       const char *method, const char *arg, int *retOut);

#endif /* CSDEV_CLR_H */
