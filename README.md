# Rainmaker C2

自研命令与控制框架。植入体、服务端、客户端三层全部自行实现，不依赖任何第三方 C2 平台。

协议为自定义的 v2 二进制协议（`CS2K`），全程 RSA-2048 密钥交换 + AES-256-CBC 加密 +
HMAC-SHA256 完整性校验；承载层支持 HTTP / HTTPS / TCP / SMB / DNS / External C2 六种，
可在运行期增删。

---

## 目录

- [核心特性](#核心特性)
- [系统组成](#系统组成)
- [通信协议](#通信协议)
- [承载层](#承载层)
- [客户端功能](#客户端功能)
- [载荷格式](#载荷格式)
- [快速开始](#快速开始)
- [构建](#构建)
- [仓库结构](#仓库结构)
- [系统要求](#系统要求)
- [安全说明](#安全说明)

---

## 核心特性

**全自研三层架构。** 植入体是 C 代码，服务端是零第三方依赖的 Go 程序（单个静态二进制），
客户端是 .NET 6 WPF 桌面程序。三者共用同一套协议实现契约（见 `docs/protocol_v2.md`），
不使用任何外部 C2 框架的组件、协议或资源。

**端到端加密。** 植入体与服务端之间以 RSA-2048 交换会话密钥（PKCS#1 v1.5 封装），
之后全部流量走 AES-256-CBC，每条消息附带 HMAC-SHA256。服务端持有私钥，
公钥在构建期编入植入体，密钥轮换后需重新生成载荷。

**六种承载层，统一协议。** HTTP、HTTPS、TCP、SMB 命名管道、DNS、External C2 共用同一套
分帧与加密逻辑，因此会话行为在各承载下完全一致。承载层可在服务端运行期通过接口增删，
无需重启。

**多操作员与访问控制。** 服务端内置操作员库，口令以加盐哈希存储（明文不落盘）。
登录换取 Bearer 令牌，令牌携带角色（admin / operator），账号管理接口仅对 admin 开放。

**Aggressor 脚本引擎。** 内置 Sleep 语言实用子集的解释器，可直接加载 `.cna` 脚本，
支持脚本资源加载、自定义菜单项、命令别名与 C2 桥接函数。

**完整的过程管理能力。** 文件浏览、进程列举、凭据管理、截屏、键盘记录、SAM hive 离线
解析、SOCKS5 代理、反向端口转发、作业调度、目标库，以及 JSON / HTML / CSV 三种格式的
活动报告导出。

---

## 系统组成

| 层 | 语言 / 运行时 | 产物 |
|---|---|---|
| 植入体 | C（Windows x64 / Linux x64） | 独立可执行文件、DLL、shellcode、脚本加载器 |
| 服务端 | Go 1.23，纯标准库 | 单一静态二进制，无运行时依赖 |
| 客户端 | C# / .NET 6 / WPF | Windows 桌面程序，15 个功能面板 |

三层之间的边界是协议，不是共享代码。服务端可独立部署于 Linux，客户端在 Windows 侧连接。

---

## 通信协议

协议 v2 的完整规范见 [`docs/protocol_v2.md`](docs/protocol_v2.md)，该文件是 C 植入体、
Go 服务端、WPF 客户端三方共同遵循的实现契约。

**帧结构。** 每帧固定 20 字节头部，后接变长消息体：

```
偏移  长度  字段
0     4     魔数 0x4353324B ("CS2K")
4     4     会话 ID
8     4     序号（单调递增）
12    4     标志位
16    4     消息体长度
20    N     消息体（加密）
```

单帧消息体上限 4 MB。超过 512 KB 的数据按分片传输，接收端按序号重组。

**密钥交换。** 植入体首次通信时生成随机 AES-256 会话密钥，用编译期内置的服务端公钥
（RSA-2048）加密后发送；服务端用私钥解出会话密钥，之后双向流量均使用该密钥。

**认证与完整性。** AES-256-CBC 加密，IV 随帧随机；HMAC-SHA256 覆盖帧头与密文，
防止篡改与重放。

**协议 v1（兼容层）。** 早期版本使用 RC4 流密码与 4 字节魔数 `KBRK`，服务端保留该通道
以兼容既有载荷。新部署建议直接使用 v2。

---

## 承载层

| 承载 | 启动参数 | 说明 |
|---|---|---|
| HTTP | 默认 | `POST /submit` 上行，`GET /task` 下行 |
| HTTPS | `-tls` | 自签名证书首次启动时自动生成 |
| TCP | `--tcp <addr>` | 裸 TCP，外层以 4 字节大端长度分帧 |
| SMB | `--smb <pipe>` | Windows 命名管道；仅 Windows 服务端支持 |
| DNS | `--dns <addr>` | TXT 查询承载，单帧上限 256 KB，适合小数据量场景 |
| External C2 | `--extc2 <addr>` | 供第三方通道对接的标准转发接口 |

承载层可在运行期通过 `POST /api/listener/add` 与 `/api/listener/del` 增删，会话不受影响。

---

## 客户端功能

单窗口 15 个面板：

| 面板 | 用途 |
|---|---|
| 会话 | 会话列表、终端、命令下发、右键菜单、sleep / jitter 调整 |
| 监听器 | 承载层实例的查看与增删 |
| 凭据 | 采集到的凭据集中管理 |
| 下载 | 从目标机取回的文件 |
| 截屏 | 屏幕截图流 |
| 键盘记录 | 键盘记录流 |
| 事件日志 | 服务端操作与状态事件 |
| 载荷生成 | 按格式生成植入体，可配置地址、端口、URI、sleep、jitter、启动口令等 |
| 文件 | 远程文件浏览器，支持上传、下载、目录导航与本地缓存 |
| 进程 | 进程列举与结束 |
| 服务端 | 操作员账号管理（需 admin 角色） |
| 目标库 | 目标主机信息维护 |
| 代理枢纽 | SOCKS5 代理与反向端口转发的建立与状态查看 |
| 脚本 | Aggressor 脚本加载、控制台与状态 |
| 作业 | 长任务的进度与结果 |

客户端启动时先显示登录界面（服务端地址、用户名、口令），认证通过后才进入主界面。

---

## 载荷格式

共 19 种，覆盖原生可执行文件、shellcode 与脚本加载器。

**协议 v2（推荐）**

| ID | 说明 |
|---|---|
| `win2-exe` | Windows x64 可执行文件（GUI 子系统） |
| `win2-console` | Windows x64 可执行文件（控制台子系统） |
| `win2-svc` | Windows x64 服务程序 |
| `win2-dll` | Windows x64 动态链接库 |
| `win2-raw` | Windows x64 shellcode |
| `win2-tcp` | Windows x64 可执行文件（TCP 直连承载） |
| `win2-ps1` | PowerShell 加载器 |
| `win2-vba` | VBA 宏 |
| `win2-vbs` | VBScript |
| `win2-cs` | C# 加载器 |
| `linux2-elf` | Linux x64 ELF（静态链接） |
| `linux2-dyn` | Linux x64 ELF（动态链接） |

**协议 v1（兼容）**

| ID | 说明 |
|---|---|
| `win-exe` / `win-console` / `win-dll` / `win-raw` / `win-ps1` | Windows 系列 |
| `linux-elf` / `linux-elf-dyn` | Linux x64 ELF（裸 TCP 承载） |

生成载荷时可选启用启动口令门控：服务端把随机盐与口令摘要编入二进制，植入体启动时校验，
明文口令不写入产物。同一口令在不同次构建中产生不同摘要。

---

## 快速开始

### 1. 获取程序

从 [Releases](https://github.com/ISrainstop/Rainmaker/releases) 下载，或自行构建（见下节）。

| 文件 | 说明 |
|---|---|
| `csdev-server.exe` | 服务端，Windows x64 |
| `csdev-server-linux-amd64` | 服务端，Linux x64 |
| `csdev-server-linux-arm64` | 服务端，Linux arm64 |
| `csdev-server-darwin-amd64` | 服务端，macOS Intel |
| `csdev-server-darwin-arm64` | 服务端，macOS Apple Silicon |
| `csdev-gui-win-x64.zip` | 客户端，Windows x64 自包含版本 |

服务端为静态链接的单一可执行文件，无需安装运行时。客户端压缩包解压后直接运行
`csdev-gui.exe`，同样无需安装 .NET 运行时。

### 2. 启动服务端

```bash
# Linux / macOS
chmod +x csdev-server-linux-amd64
./csdev-server-linux-amd64 -port 8443

# Windows
csdev-server.exe -port 8443
```

首次启动会自动生成 RSA 密钥对、操作员库与随机的默认管理员口令。**该口令只打印一次**，
请立即保存。

服务端启动后可访问 `http://127.0.0.1:8443/` 使用内置 Web 界面。

> 服务端的访问控制默认开启。`-auth=off` 会完全旁路鉴权，仅用于隔离测试环境。

### 3. 连接客户端

解压 `csdev-gui-win-x64.zip`，运行其中的 `csdev-gui.exe`，在登录界面填入服务端地址、
用户名与口令。

### 4. 生成载荷

在客户端「载荷生成」面板选择格式，填写回连地址与端口，点击生成。
产物默认输出到 `build/payload/`。

### 5. 建立会话

在目标机执行生成的可执行文件，会话将出现在「会话」面板，选中后即可在下方终端下发命令。

---

## 构建

### 服务端（全平台）

服务端是零第三方依赖的 Go 程序，交叉编译不需要目标平台工具链。

```bash
pwsh -File tools/build_server.ps1 -Verify
```

一次产出五个平台的静态二进制，落在 `build/`：

```
csdev-server.exe                Windows  amd64
csdev-server-linux-amd64        Linux    amd64
csdev-server-linux-arm64        Linux    arm64
csdev-server-darwin-amd64       macOS    amd64
csdev-server-darwin-arm64       macOS    arm64
```

也可直接用 Go 命令：

```bash
cd go
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o csdev-server-linux-amd64 .
```

### 客户端

需要 .NET 6 SDK 与 Windows：

```bash
cd gui
dotnet build -c Release
```

自测（离线，不连接服务端）：

```bash
csdev-gui.exe --selftest
```

### 植入体

生成植入体需要目标格式对应的 C 工具链：

| 目标 | 工具链 |
|---|---|
| Windows x64 | MinGW-w64（`gcc` 需在 PATH 中，或用 `-MinGw` 指定目录） |
| Linux x64 | `gcc` |

生成流程由客户端「载荷生成」面板驱动，服务端调用 `tools/gen_payload2.ps1` 完成编译与打包。

---

## 仓库结构

```
go/                   服务端（Go）
  proto/              协议实现：分帧、加密、密钥交换
  profile/            Malleable C2 profile 解析
  testdata/           测试样本

gui/                  客户端（C# / .NET 6 / WPF）
  App.xaml            主题与控件样式（浅色主题，语义化设计令牌）
  MainWindow.xaml     主窗口与 15 个面板
  SelfTest.cs         离线自测套件

kits/                 植入体与支撑模块（C）
  beacon/             Windows 植入体核心
  crypto/             AES / SHA-256 / RSA
  proto/              协议分帧
  packer/             加载器、stager、CLR 宿主
  artifact/           PE 载体模板
  evasion/            反调试与反沙箱
  injector/           注入器
  sleepmask/          睡眠期内存伪装
  udrl/               反射加载器

linux/                Linux 植入体（C）与配套服务端
c2/                   早期 Python 服务端实现
aggressor/            Aggressor 插件
profiles/             Malleable C2 profile
tools/                构建与生成脚本
docs/                 协议规范
```

---

## 系统要求

| 组件 | 要求 |
|---|---|
| 服务端 | 无需运行时。可运行于 Windows 10+ / Linux（amd64、arm64）/ macOS（amd64、arm64） |
| 客户端 | Windows 10 或 11，需 .NET 6 桌面运行时 |
| 植入体（Windows 目标） | 构建需 MinGW-w64；产物运行于 Windows x64 |
| 植入体（Linux 目标） | 构建需 `gcc`；产物运行于 Linux x64（静态链接版本无 glibc 版本要求） |

**平台差异。** SMB 承载基于 Windows 命名管道，仅 Windows 服务端提供；在 Linux / macOS 上
选择该承载会返回明确的平台限制提示，不影响其他五种承载与会话功能。

---

## 安全说明

本项目是安全测试工具，**仅供已获得明确授权的渗透测试、红队演练与安全研究使用**。

- 未经授权对他人系统使用本工具可能违反法律。
- 使用者有责任确认测试范围与授权状态。
- 服务端默认开启访问控制，请勿以 `-auth=off` 暴露于非受信网络。
- 敏感数据（RSA 私钥、操作员库、采集结果）默认写入 `data/`，已被 `.gitignore` 排除，
  请勿随仓库分发。
- 密钥轮换（重新生成 `data/csdev.key`）后，全部既有载荷失效，需重新生成。

---

## 文档

| 文档 | 内容 |
|---|---|
| [`docs/protocol_v2.md`](docs/protocol_v2.md) | 协议 v2 规范：帧结构、加密、密钥交换、消息类型 |
| [`HANDOVER.md`](HANDOVER.md) | 项目技术档案：架构决策、模块边界、已知限制与后续方向 |
