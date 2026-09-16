# CS 二开免杀套件 (cs_dev)

Cobalt Strike 4.7 二次开发套件 —— 自研免杀模块、可选择的免杀档案、跨平台载荷支持。

---

## 一、项目状态

**当前成果：多引擎检测 0 检出**（最终版本 `stager.exe` 20480 字节）

| 检测引擎 | 初始状态 | 当前状态 |
|---|---|---|
| Kaspersky | `HEUR:Trojan.Win32.CobaltStrike.gen` | **已消除** |
| GDATA | `Dump:Generic.Beacon.Marte.B.18C12973` | **已消除** |
| OneAV | `Win.Suspicious.ml[pua]` | **已消除** |
| Baidu-China | `Win32.Trojan.WisdomEyes.151026.9950.9998` | **已消除** |
| ESET | `a variant of Win64/CobaltStrike.Artifact` | **已消除** |

---

## 二、自研组件清单

| 组件 | 文件 | 说明 |
|---|---|---|
| 载体 PE 壳 | `kits/artifact/artifact64.c` | 6 变体 (exe/svc/dll × small/big)，体积 0.92~1.48 倍原版 |
| Payload 加载器 | `kits/packer/csdev_loader.c` | RC4 + 节区内嵌配置 |
| **自研 Stager** | `kits/packer/csdev_stager.c` | **WinHTTP + 独立线程执行 stage** |
| sleep mask | `kits/sleepmask/sleepmask.c` | RC4 + 变步长 XOR |
| injector | `kits/injector/injector.c` | 硬件断点 patchless + RecycledGate |
| UDRL | `kits/udrl/udrl.c` | 自定义反射加载器 |
| evasion 头文件 | `kits/evasion/hwbp.h`, `evasion.h` | 反调试/反沙箱/调用栈伪造 |
| Linux beacon | `linux/beacon.c`, `stager.c` | 独立 Linux 载荷 + 配套 C2 服务端 |
| 主插件 | `aggressor/cs_dev.cna` | 19 个 sub，4 个菜单入口 |
| C2 Profile | `profiles/csdev.profile` | 规避默认 profile 特征 |

---

## 三、逆向发现（全部实测验证）

### 3.1 CS stager 机制

```
模板文件    : resources/httpsstager64.bin (909 字节)
配置偏移    : port=274  flags=314  exitOffset=811  skipOffset=898
网络栈      : WinINet
X/Y 占位符  : 0x58='pop rax' / 0x59='pop rcx' —— 填充指令, 非数据缓冲区
解密环节    : 无 (stage 由 stage 自身处理)
```

### 3.2 stage 下载的四个关键机制

| # | 机制 | 实测证据 |
|---|---|---|
| 1 | **URI 必须满足 checksum8** | `/aaa`(ck8=35) → 404 |
| 2 | **checksum8 数值决定 stage 架构** | **92 → x86 (MZRE 头, 223302 字节)<br>93 → x64 (纯 shellcode, 277063 字节)** |
| 3 | **必须带特定请求头** | 缺 `Accept`/`Connection`/`Cache-Control` → 404 |
| 4 | **stage 必须在独立线程执行** | 主线程执行可上线但**命令通道不通** |

checksum8 算法：去掉斜杠后各字符 ASCII 之和，对 256 取余。

### 3.3 stage 自解密 stub

```
0x00: FC              cld
0x01: E8 0A 00 00 00  call 0x10
0x10: EB 27           jmp  0x39
0x39: E8 D4 FF FF FF  call 0x12
0x12: 5B              pop  rbx        ; rbx = 0x3E (自身定位)
0x13: 8B 2B           mov  ebp,[rbx]  ; XOR 密钥
...                   (链式 XOR 解密循环)
0x37: FF E5           jmp  rbp        ; 跳入明文
```

还原工具：`tools/unpack_stage.py`

---

## 四、免杀优化链（按时间顺序）

| # | 消除的特征 | 手段 |
|---|---|---|
| 1 | CS stager 909 字节模板代码 | 自研 WinHTTP stager 完全替代 |
| 2 | 尾部附加数据 (overlay) | 配置迁入 `.data` 节区内嵌 |
| 3 | 自读取行为链 | 移除 `GetModuleFileNameA`/`CreateFileA`/`ReadFile`/`GetFileSize` |
| 4 | RC4 S-box 特征 | 改为异或流 |
| 5 | 反调试特征对 | 移除 `IsDebuggerPresent`/`CheckRemoteDebuggerPresent` |
| 6 | **PE 内预留区形态** | **`.data` 内 2048 字节零区改为伪随机初始化** |
| 7 | MinGW 节名指纹 | 6 个节名偏离 CS 原版 |

### 关键教训

第 6 项是转折点，但它的发现过程值得记录：

- 修 Baidu 时我把配置从 overlay 搬进 `.data` 预留区
- **Baidu 消失了，但 ESET 出现了** —— 是我自己的改动引入了新检测
- 原因是**全零预留区的形态与 CS artifact 机制相同**（CS 预留 1024 个 `'A'`，我预留 2048 字节零区）
- 改为伪随机初始化后 ESET 立即失效

**方法论**：检测结果的时间序列本身就是定位依据。连续往前改而不回头对照"哪次改动引入了新检测"，会导致多轮空转。

---

## 五、关键约束（无法规避）

| 约束 | 原因 |
|---|---|
| **RWX 权限必须保留** | stage 是自解密 shellcode，运行期需写自身；实测改 RX 立即 `0xC0000005` |
| **WinHTTP 四件套无法移除** | 下载 stage 的功能本体 |
| **`VirtualAlloc`+`VirtualProtect`+`CreateThread` 无法移除** | 执行 stage 的功能本体 |
| **1024 个 `'A'` 锚点无法消除** | 若走 CS artifact 路径，CS 用 `indexOf("A"*1024)` 硬编码定位；唯一出路是不用该路径 |
| **32 位模板未改造** | 本机无 i686 工具链 |

---

## 六、使用方法

### 6.1 部署插件

把 `plugin/cs_dev/` 整个目录放到 CS 根目录的 `plugin/` 下，重启客户端自动加载。

### 6.2 生成自研 stager

```
菜单: Payloads -> 免杀档案 (cs_dev) -> 自研 Stager 生成 (无CS模板)
参数: C2 地址 / 端口 / URI / 协议
URI  : x64 必须用 checksum8=93 (如 /aab9 /aac8 /aad7)
       x86 用 checksum8=92 (如 /aaa9 /aab8)
```

生成后拷到目标机执行即可回连，命令通道正常。

### 6.3 切换免杀档案

```
菜单: 免杀档案 -> 基础/进阶/对抗
说明: 切换后需重启客户端 (Windows kits 在启动时从 jar 加载)
档案: basic (2384B) / advanced (5264B) / stealth (5520B)
```

### 6.4 CrossC2 (Linux 载荷进 CS 会话)

```
菜单: Linux 载荷 -> CrossC2 生成
前提: 需先连过 teamserver 生成 .cobaltstrike.beacon_keys
注意: listener 必须是 HTTPS 类型, HTTP listener 不会有会话
```

### 6.5 加载自定义 Profile

**Profile 由 teamserver 加载，客户端无法加载**（客户端 `Help -> Malleable C2` 只是只读查看）。

```bash
# 服务器上
./teamserver <绑定IP> <密码> /path/to/csdev.profile
```

注意：**已有 listener 不会自动更新**，需删掉重建。

---

## 七、工具说明

| 工具 | 用途 |
|---|---|
| `tools/build_stager.ps1` | 生成自研 stager（含改节名、节区内嵌配置） |
| `tools/pack_payload.ps1` | 把 raw shellcode 打包成 EXE |
| `tools/build_library.ps1` | 预编译全部免杀档案变体 |
| `tools/apply_profile.ps1` | 从变体库快速切换档案 |
| `tools/deploy.ps1` | 编译并部署到 jar |
| `tools/SleeveCrypt.java` | CS sleeve 资源加解密 |
| `tools/ParseBeaconKeys.java` | 解析 beacon_keys 提取 RSA 公钥 |
| `tools/unpack_stage.py` | 还原 stage 自解密 stub |
| `tools/ValidateProfile.java` | Profile 语法校验 |
| `tools/gen_linux.ps1` | 生成独立 Linux 载荷 |

---

## 八、工程注意事项

1. **所有 `.ps1` 必须带 UTF-8 BOM** —— PowerShell 5.1 用 GBK 读取无 BOM 文件会导致中文乱码进而语法错误
2. **CNA 的 `exec()` 是异步的** —— 脚本报错不会回到 CS 控制台
3. **菜单项不能有颜色码** —— `\cXX` 只在 `println` 中生效
4. **`show_message` 单参数**
5. **CNA 路径用正斜杠** —— 反斜杠会被当转义符

---

## 九、未完成项

- 32 位载体（6 个模板）未改造，缺 i686 工具链
- 自研 stager 只做过功能验证，无长期稳定性测试
- Profile 未在真实 teamserver 上验证加载效果
- 换 MSVC 工具链重编的方案未实施（可能对更深层的编译器指纹检测有效）
