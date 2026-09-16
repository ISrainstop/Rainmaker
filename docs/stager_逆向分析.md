# CS stager 生成机制 —— 逆向分析报告

> 分析方法: 反编译 `cobaltstrike-client.jar` 中的 `stagers/*` 类, 并解析
> `resources/*.bin` 模板结构。全部结论来自实测数据, 非推测。

## 一、结论摘要

**关键认知修正**: CS 的 stager **不执行 RSA metadata checkin**。

RSA 加密的 metadata 握手属于 **Beacon(stage) 阶段**, 由 stage 内部的
Beacon DLL 完成。stager 本身只做四件事:

```
读取配置 -> 发起 GET 请求 -> 接收 stage -> 解密并跳转执行
```

这个认知把自研 stager 的工程量从"复刻整套加密握手协议"降到"实现一个
HTTP 下载器"。原先预估的数万行协议代码是不必要的。

## 二、模板配置偏移 (实测)

`GenericHTTPSStagerX64` 反编译得到的硬编码偏移:

| 方法 | 返回值 | 含义 |
|---|---|---|
| `getPortOffset()`   | 274 | 写入监听端口 (4 字节小端) |
| `getFlagsOffset()`  | 314 | 写入连接标志位 |
| `getExitOffset()`   | 811 | 退出代码偏移 |
| `getSkipOffset()`   | 898 | 跳过偏移 |
| `getStagerFile()`   | `resources/httpsstager64.bin` | 模板文件 |

x86 对应文件为 `resources/httpsstager64.bin` 之外的 `httpstager.bin` 系列。

## 三、模板实测结构

`resources/httpsstager64.bin` = **909 字节**, 零字节仅 45 个 (高密度代码)。

内置占位符经反汇编确认为**填充指令**, 而非数据缓冲区 (修正早期推测):

| 占位符 | 字节值 | 反汇编结果 | 用途 |
|---|---|---|---|
| `X` 连续串 | 0x58 | `pop rax` | 预留替换位 |
| `Y` 连续串 | 0x59 | `pop rcx` | 预留替换位 |

即 CS 在 generate 阶段把这两段填充替换成实际的跳转或对齐代码,
它们不是 URI 缓冲区。

偏移 274 实测值 `5C 11 00 00` = **0x115C = 4444**, 与 CS 默认监听端口一致,
确认该字段即端口。

字符串表中出现 **`wininet`**, 说明 stager 通过 WinINet 发起 HTTP(S) 请求,
不使用自实现 socket 栈。

## 三点五、无 stage 解密环节 (关键)

对模板做全量反汇编 (565 行), 结果:

- **不存在 XOR 解密循环**。唯一的 `loop` 指令位于 0x3e, 属于早期初始化段。
- 全部 12 处 `call` 中, 10 处为 `call rbp` 形式的 API 间接调用, 3 处为
  本地短调用 (0xd2 / 0x12b / 0x10c), 无解密例程特征。

**结论**: CS 4.x 的 HTTP(S) stager 收到响应后**不做解密**, 仅跳过
`getStagePreamble()` 指定的前导长度, 随即跳转执行 stage。

这消除了自研 stager 的最后一项未知。自研 stager 的完整规格因此收敛为:

```
读取 host/port/URI 配置
  -> 发起 HTTP(S) GET
  -> 接收响应到缓冲区
  -> 跳过 preamble 长度
  -> 跳转执行
```

**不涉及**: RSA 加密、metadata 构造、会话密钥协商、XOR 解密。

这些全部属于 stage(Beacon DLL)阶段, 由 CS 自己的 stage 完成 —— 而 stage
不需要自研, 保留 CS 原样即可, 功能完整性不受影响。

## 四、连接标志位构成

`GenericHTTPStager.getConnectionFlags()` 反编译结果:

| 标志值 | 十六进制 | 条件 |
|---|---|---|
| -2147483648 | 0x80000000 | 恒定 |
| 67108864 | 0x04000000 | 恒定 |
| 512 | 0x00000200 | 恒定 |
| 4194304 | 0x00400000 | 恒定 |
| 8388608 | 0x00800000 | 仅 SSL (HTTPS) |
| 4096 | 0x00001000 | 仅 SSL |
| 8192 | 0x00002000 | 仅 SSL |
| 524288 | 0x00080000 | 仅 usesCookie |

判定 SSL 的方式: 类名中包含子串 `HTTPSStager`。
`getStagePreamble()` 返回 `ListenerConfig.getHTTPStageOffset()`, 即 stage
数据中需跳过的前导长度。

## 五、URI 构造

`BeaconHTTPSStagerX64.getURI()`:

```
URI = ListenerConfig.getURI_X64() + ListenerConfig.getQueryString()
```

`payload()` 返回 `windows/beacon_https/reverse_https`。

## 六、生成调用链

```
Stagers.shellcode(listener, arch, ...)
  -> Stagers.resolve(listener, ...)   选择对应 GenericStager 子类
  -> GenericStager.generate()          产出 stager shellcode
```

`resolve()` 依据特征串在整个 registry 中匹配, registry 涵盖:

```
BeaconHTTPSStagerX64 / X86
BeaconHTTPStagerX64  / X86
BeaconBindStagerX64  / X86
BeaconDNSStagerX86
BeaconPipeStagerX86
ForeignHTTPSStagerX86 / ForeignHTTPStagerX86
ForeignReverseStagerX64 / X86
```

## 七、对自研方案的影响

**已可自研**:

1. 载体 PE 壳 (已完成, 6 变体, 体积 0.92~1.48 倍原版)
2. Payload 加载器 (已完成, RC4 + 尾部 overlay + 反调试)
3. 打包器 (已完成, 端到端验证通过)
4. RSA 公钥提取 (已完成, 1024-bit, e=65537, 已导出为 C 头文件)
5. **stager 下载跳转逻辑 —— 本报告已完全扫清, 无任何协议握手或解密负担**

**不需要自研**:

- Beacon 本体(stage)。CS 不公开其源码, 且复刻其协议风险极高
  (CrossC2 即为该路线成品, 其版本错配导致"上线但命令不通")。
  保留 CS 原 stage 可确保功能 100% 完整。

## 八、下一步: 自研 stager 的实现要点

规格已收敛为 HTTP 下载器 + 跳转, 实现需处理:

1. **配置注入**: 沿用 CS 的偏移约定 (274 端口 / 314 标志 / 811 exit /
   898 skip), 或改用自定义配置布局 —— 后者可彻底摆脱 CS 模板特征。
2. **请求构造**: `GET <URI_X64><QueryString>`, 携带 profile 定义的 Header
   与 User-Agent, 经 WinINet 或自实现 socket 发出。
3. **响应处理**: 读入缓冲区, 按 `getHTTPStageOffset()` 跳过前导,
   跳转执行。
4. **特征消除目标**: 不再使用 `httpsstager64.bin` 的 909 字节固定代码,
   因此卡巴 `HEUR:Trojan.Win32.CobaltStrike.gen` 所依赖的 stager 代码
   模式将不复存在。

## 九、方法论说明

本报告全部结论来自对本机 `cobaltstrike-client.jar` 的反编译与模板实测,
未依赖外部资料。核心工具为 `javap -c -constants` 与 `objdump -D -b binary`。
早期关于 `X`/`Y` 占位符用途的推测已被反汇编结果推翻并修正, 以本版为准。

