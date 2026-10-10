# Rainmaker C2 协议 v2 规范 (CS2K)

> 本文件是**实现契约**。C 植入体、Go 服务端、WPF GUI 三方均以本文件为准。
> 任何字段顺序、字节序、覆盖范围不得单方面修改；改动必须先改本文件。

---

## 0. 设计目标与硬约束

| 目标 | 说明 |
|---|---|
| 每会话独立密钥 | 不再使用编译期硬编码共享 RC4 密钥（v1 的根本缺陷） |
| 密文完整性 | HMAC-SHA256 覆盖帧头 + IV + 密文，篡改即拒 |
| 防重放 | 帧内 `seq` 单调递增，服务端按会话记录已见 seq |
| 二进制安全 | 用 TLV 承载，支持任意字节（文件、COFF、截屏） |
| 多通道同构 | HTTP/HTTPS/TCP/SMB/DNS 共用同一帧格式，仅承载层不同 |
| **不新增 DLL 导入** | 保持 `ADVAPI32 + KERNEL32 + msvcrt + WINHTTP` 四件套，保护既有免杀成果 |

**禁止事项**：协议 v2 的实现代码不得引入 `bcrypt.dll`、`crypt32.dll`、`ws2_32.dll`（Windows 植入体）之外的新依赖；
AES/SHA256/HMAC 一律自实现（`kits/crypto/`）。

---

## 1. 密码学原语

| 用途 | 算法 | C 侧实现 | Go 侧实现 |
|---|---|---|---|
| 密钥交换 | RSA-2048 / PKCS#1 v1.5 | CryptoAPI `CryptEncrypt`（ADVAPI32，已在导入表） | `crypto/rsa.DecryptPKCS1v15` |
| 对称加密 | AES-256-CBC + PKCS#7 | 自研 `kits/crypto/aes.c` | `crypto/aes` + `cipher` |
| 完整性 | HMAC-SHA256 | 自研 `kits/crypto/sha256.c` + `hmac.c` | `crypto/hmac` + `crypto/sha256` |
| 随机数 | CSPRNG | `CryptGenRandom` | `crypto/rand` |

### 1.1 会话密钥材料（每会话独立，植入体生成）

```
aes_key   32 字节   随机
hmac_key  32 字节   随机
```

### 1.2 服务端密钥对

- 首次启动生成 RSA-2048，落盘 `data/csdev.key`（PKCS#8 PEM）与 `data/csdev.pub`（PKIX PEM）。
- **生成载荷时**，生成器从 `data/csdev.key` 现算 **CryptoAPI PUBLICKEYBLOB** 并覆写进载荷配置槽
  （见 §1.3 `pubkey` 字段），保证载荷与服务端私钥**永远同源**——不再需要手动同步 `pubkey.h`。
- `pubkey.h` 与 `--emit-pubkey` 退化为**手工 gcc 编译时的回退公钥**，仅供无生成器的本地联调用。

```
# 手工 gcc 编译回退公钥（可选；生成器产出的载荷会自动带服务端当前公钥）
csdev-server.exe --emit-pubkey C:\csdev-c2\kits\beacon\pubkey.h
```

PUBLICKEYBLOB 布局（**小端**）：

```
BLOBHEADER  bType=0x06  bVersion=0x02  reserved=0x0000  aiKeyAlg=0x0000A400 (CALG_RSA_KEYX)
RSAPUBKEY   magic="RSA1"(0x31415352)  bitlen=2048  pubexp=65537
modulus     256 字节，**小端**（Go 侧需对 big.Int 做字节序反转）
```

C 侧直接 `CryptImportKey(hProv, blob, sizeof(blob), 0, 0, &hKey)`，无需解析。

### 1.3 载荷配置槽（C2_RUNTIME_CFG，合计 1024 字节）

植入体把运行期可变配置放在独立节 `.c2cfg` 里，生成器在二进制里扫描 8 字节高熵标记
（`52 47 43 32 A5 5A C3 3C`，全文件**恰好命中一次**）后按偏移覆写。布局与
`go/gen_native.go` 的常量表、`gui/NativeGenerator.cs` 逐字节对应：

| 偏移 | 长度 | 字段 | 说明 |
|---|---|---|---|
| 0 | 8 | `magic` | 定位标记 |
| 8 | 4 | `version` | `C2_CFG_VERSION = 2`；非 2 视为未启用 |
| 12 | 4 | `port` | 回连端口 |
| 16 | 4 | `sleep_ms` | 心跳间隔 |
| 20 | 4 | `jitter` | 抖动百分比 |
| 24 | 4 | `flags` | bit0 = TLS |
| 28 | 4 | `nonce` | 每次生成随机，避免同配置产物哈希相同 |
| 32 | 128 | `host` | 回连地址 |
| 160 | 64 | `uri` | 上行路径 |
| 224 | 32 | `xform` | body 变换链（`raw` / `base64` 等） |
| 256 | 24 | `token_salt` | 启动口令盐（空 = 不启用门控） |
| 280 | 72 | `token_hash` | SHA256(盐||口令) |
| 352 | 48 | `id_header` | metadata 头名 |
| 400 | 80 | `id_value` | metadata 头值 |
| 480 | 276 | `pubkey` | CryptoAPI PUBLICKEYBLOB；**全 0 = 回退 §1.2 的 `pubkey.h`** |
| 756 | 268 | `reserved` | 预留（生成时清零） |

植入体侧 `c2cfg_pubkey()`：槽位 `version==2` 且 `pubkey` 非全 0 时用槽位公钥，否则回退编译期
`CSDEV_PUBKEY_BLOB`。因此手工 gcc 编译的模板不带 pubkey 也能跑（用 `pubkey.h`），而生成器产出的
载荷永远带服务端当前公钥。

---

## 2. 帧格式

### 2.1 通用帧头（固定 20 字节，网络序 BE）

| 偏移 | 长度 | 字段 | 说明 |
|---|---|---|---|
| 0 | 4 | `magic` | 固定 `0x4353324B`（ASCII `"CS2K"`） |
| 4 | 4 | `session_id` | checkin 帧为 `0`；否则为服务端分配的会话号 |
| 8 | 4 | `seq` | 该会话内单调递增（从 0 起）；checkin 为 0 |
| 12 | 4 | `flags` | 位标志，见下 |
| 16 | 4 | `body_len` | 其后 body 的总字节数 |

`flags` 位定义：

| 位 | 名称 | 含义 |
|---|---|---|
| 0 | `F_CHECKIN` | 本帧为首次上线（RSA 加密 body） |
| 1 | `F_HASRESULT` | 上行帧携带结果 TLV |
| 2 | `F_CHUNKED` | 携带文件分块 |
| 3 | `F_ERROR` | 服务端应答中的错误标记 |
| 4 | `F_NOHMAC` | 显式声明无 HMAC（仅 checkin 与空应答使用） |

### 2.2 上行帧 body

```
非 checkin：  [16B IV][AES-256-CBC 密文][32B HMAC]
              hm_len = 16 + ct_len + 32      (ct_len 为 16 的整数倍)
checkin：     [RSA-2048/PKCS1v15 密文]       (固定 256 字节)
```

**HMAC 覆盖范围（必须逐字节一致）**：

```
HMAC_input = 帧头(20 字节原样) || IV(16 字节) || 密文
HMAC       = HMAC-SHA256(key = hmac_key, HMAC_input)
```

帧头中的 `body_len` 参与计算，因此编码顺序必须是：先算密文 → 填 `body_len` → 再算 HMAC。

### 2.3 checkin 明文结构

```
偏移  长度  字段
0     32    aes_key
32    32    hmac_key
64    16    iv_seed（保留，用于兼容旧实现，可全 0）
80    1     协议版本 = 0x02
81    1     meta 长度
82    n     meta（ASCII，字段以 0x1F 分隔）
```

`meta` 字段顺序（0x1F 分隔）：

```
host \x1F user \x1F arch \x1F pid \x1F ppid \x1F procname \x1F internal_ip \x1F os_ver
```

服务端对 checkin 的应答：**普通帧**（`flags` 清 `F_CHECKIN`），body 为 AES 加密的 TASK_BATCH（可为空批次）。

### 2.4 应答帧 body

```
[AES 密文 + HMAC]，结构同 2.2 非 checkin 分支
空应答：flags |= F_NOHMAC，body_len = 0
```

服务端在应答中总是返回：当前待执行任务批次（`TASK_BATCH`），无任务时为空批次（`count = 0`）。

---

## 3. TLV

```
[2B type][4B len][len 字节 data]        均为网络序
```

type 高字节表类别，低字节表具体项。

> **len 为 4 字节（2026-09 修订）**。原设计用 2 字节，上限 65535，与第 7 节的
> `CHUNK_SIZE = 512 KB` 直接冲突：分块长度会被静默截断成低 16 位，服务端解析出
> 随机 type 并报"数据截断"。实测现象是截屏回传全部失败、小文件（<64 KB）正常。
> 两侧实现（`kits/proto/frame.c`、`go/proto/tlv.go`）已同步为 4 字节。

### 3.1 上行（植入体 → 服务端）

| type | 名称 | data |
|---|---|---|
| `0x1001` | HEARTBEAT | `[8B unix_ms]` |
| `0x1002` | RESULT | RESULT 结构（见 4.2） |
| `0x1003` | FILE_CHUNK | `[4B job_id][4B offset][4B total][bytes]` |
| `0x1004` | PROXY_DATA | `[4B chan_id][bytes]` |
| `0x1005` | KEYLOG | UTF-8 文本 |
| `0x1006` | SCREEN | JPEG 字节 |
| `0x1007` | META_UPDATE | 同 checkin 的 meta 字符串 |
| `0x1008` | CREDENTIAL | `[1B kind][2B user_len][user][2B secret_len][secret][2B source_len][source]` |

### 3.2 下行（服务端 → 植入体）

| type | 名称 | data |
|---|---|---|
| `0x2001` | TASK | TASK 结构（见 4.1） |
| `0x2002` | CHUNK_ACK | `[4B job_id][4B next_offset]` |
| `0x2003` | PROXY_DATA | `[4B chan_id][bytes]` |
| `0x2004` | SET_SLEEP | `[4B sleep_ms][1B jitter_pct]` |
| `0x2005` | KILL | 空 |

---

## 4. 任务与结果

### 4.1 TASK

```
偏移  长度  字段
0     4     task_id      服务端分配，单调递增
4     1     cmd_class    见下表
5     2     alias_len
7     n     alias        ASCII 命令名（用于日志与结果标注）
7+n   4     arg_len
11+n  m     arg          类别相关
```

`cmd_class` 枚举：

| 值 | 名称 | arg 语义 |
|---|---|---|
| `0x01` | EXEC_SHELL | shell 命令行（服务端已做别名映射） |
| `0x02` | FILE_DL | 待下载的远端路径 |
| `0x03` | FILE_UP | `[2B path_len][path][4B total][4B offset][bytes]` |
| `0x04` | PROC_LIST | 空 |
| `0x05` | EXIT | 空 |
| `0x06` | SET_SLEEP | `[4B sleep_ms][1B jitter]` |
| `0x07` | INJ_PROC | TLV 子结构：`0x3001=pid(4B)`、`0x3002=method(1B)`、`0x3003=payload`、`0x3004=args` |
| `0x08` | INJ_BOF | TLV 子结构：`0x3005=coff 字节`、`0x3006=参数块`、`0x3007=入口名` |
| `0x09` | INJ_ASSEMBLY | TLV 子结构：`0x3008=assembly`、`0x3009=参数` |
| `0x0A` | TOKEN | `[1B op][op 相关]`（1=steal,2=make,3=rev2self,4=getuid,5=getprivs,6=impersonate） |
| `0x0B` | PROXY | `[4B chan_id][1B op][op 相关]`（1=open,2=data,3=close） |
| `0x0C` | KEYLOG | `[1B 0=stop,1=start]` |
| `0x0D` | SCREENSHOT | 空 |
| `0x0E` | PERSIST | `[1B mode][target]` |
| `0x0F` | PS_LIST | 空（增强进程列表，含架构/路径/用户） |
| `0x10` | FS_OPS | `[1B op][路径]`（ls/cd/pwd/rm/mkdir/cat/timestomp） |
| `0x11` | NET_OPS | `[1B op][参数]` |
| `0x12` | PORTSCAN | `[2B hosts_len][hosts][2B ports_len][ports][1B method]` |
| `0x13` | RPORTFWD | `[1B op][2B bind][2B target]` |
| `0x7F` | CUSTOM | 插件扩展，arg 自定义 |

### 4.2 TASK_BATCH（服务端 → 植入体，AES 明文内）

```
[4B count]
count × [4B task_len][task 字节]
```

### 4.3 RESULT（植入体 → 服务端）

```
[4B task_id][1B status][4B out_len][out]
status: 0=OK  1=ERR  2=PARTIAL（后续分块）  3=BUSY
```

### 4.4 任务执行模型（异步）

植入体把长阻塞命令（`EXEC_SHELL` / `INJ_PROC` / `INJ_BOF` / `INJ_ASSEMBLY` / `TOKEN` /
`PORTSCAN`）放入**独立 worker 线程**执行，心跳主循环只做「睡眠 → 泵 → 收发 → 派发」，
因此单条慢命令不会堵死通信；结果通过受临界区保护的 outbox 原子追加，随下一轮上行帧带回。

涉及模块状态机的命令（`KEYLOG` / `SCREENSHOT` / `PROXY` / `FILE_DL` / `RPORTFWD`）仍在主循环
同步执行（它们的 pump 跑在主循环上，跨线程会破坏状态）。服务端无需感知该调度差异——任务
语义与 RESULT 回传完全不变。

---

## 5. 通道与 URI

### 5.1 默认 URI（无 profile 时）

| 用途 | 方法 | 路径 |
|---|---|---|
| 提交（上行含结果）+ 取任务 | POST | `/submit` |
| 独立取任务（兼容/低频） | POST | `/task2` |

v1（`/report` `/task` `/result`）作为 **legacy listener** 继续服务旧植入体，两者共存不冲突。

### 5.1b 承载层无关性（TCP listener）

帧格式与承载层解耦。TCP 通道上帧以 `[4B 长度][帧字节]` 分帧，其余（加密、TLV、
任务批次）与 HTTP 完全相同。植入体侧编译期宏 `C2_TRANSPORT`（`http` / `tcp`）选择
承载层；服务端对应 listener 类型 `tcp`。

```
HTTP:  POST <uri>       body = transform(frame)
TCP :  <连接>           流 = [4B len][transform(frame)] 重复
```

### 5.2 Malleable profile 覆盖

**已实现**（2026-09）

| 能力 | 服务端 | 植入体侧 |
|---|---|---|
| 入口 URI 池 | 按 `http-post/client` 与 `http-get/client` 的 `set uri` 列表注册全部路径 | 生成器 `-Uri` 写入编译期 `C2_URI` |
| 应答头 | 按 `http-post/server` 的 `header` 设置 | 不适用 |
| useragent / sleeptime / jitter | 读取并在启动日志与 `/api/state` 暴露 | 生成器 `-Sleep` / `-Jitter` |
| **body 变换链** | `http-post/client/output` 用于上行（逆变换）<br>`http-post/server/output` 用于下行（正变换） | 编译期 `C2_XFORM`，必须与 profile 一致 |

变换链支持 `raw` / `base64` / `base64url` / `netbios` / `netbiosu` / `mask`，
链式以 `+` 分隔（最多 4 级），例如 `base64+mask`。
实现两侧对标：`kits/beacon/xform.c` ↔ `go/profile/model.go`。
示例档：`profiles/csdev_http_b64.profile`。

> **一致性要求**：profile 声明 `base64` 而植入体按 `raw` 编译时，帧会解析失败
> （现象：植入体不上线或命令无回传，服务端日志报帧解析错误）。
> 这是设计上的约束，不是缺陷 —— 两侧的变换必须由同一次生成动作同时决定。

**未实现**：`metadata` / `id` 的独立变换与放置（`header` / `parameter` / `uri-append`）、
`http-stager` 块、`process-inject` / `post-ex` 的行为开关、`prepend` / `append` 字面量。

---

## 6. 节奏控制

| 参数 | 默认 | 说明 |
|---|---|---|
| `sleep_ms` | 5000 | 两次 beacon 间隔 |
| `jitter_pct` | 10 | 间隔抖动百分比，实际间隔 = sleep × (1 ± jitter/100) |
| `working_hours` | 空 | 格式 `"08:00-18:00:1,2,3,4,5"`（时段:星期）；非工作时段 sleep 加倍 |
| `kill_date` | 0 | Unix 秒；到期植入体自毁 |

植入体可在运行时通过 `SET_SLEEP` 任务热更新（服务端下发）。

---

## 7. 分块传输

- 单块上限 `CHUNK_SIZE = 512 KB`；单帧上限 4 MB。
- 下载：植入体按 `FILE_CHUNK` 逐块上行，每块 `[job_id][offset][total][bytes]`；服务端写盘并在有窗口时回 `CHUNK_ACK`。
- 上传：服务端逐块下发 `FILE_UP` 任务；植入体写盘后回 RESULT（`status=2` 表示继续），服务端据 `next_offset` 推进。
- 截屏走同一条 `FILE_CHUNK` 通道，文件名以 `screen_` 前缀标识，服务端据此额外入截屏库。

---

## 8. 命令类别路由（服务端）

v1 的 111 条别名全部保留；v2 新增**类别路由表**：命令名 → `cmd_class`。

```
ps        -> 0x0F PS_LIST        (原生，带架构与用户)
ls/cd/pwd -> 0x10 FS_OPS         (原生，结构化输出)
download  -> 0x02 FILE_DL
upload    -> 0x03 FILE_UP
screenshot-> 0x0D SCREENSHOT
keylog    -> 0x0C KEYLOG
inject    -> 0x07 INJ_PROC
bof       -> 0x08 INJ_BOF
token     -> 0x0A TOKEN
socks     -> 0x0B PROXY
portscan  -> 0x12 PORTSCAN
rportfwd  -> 0x13 RPORTFWD
其余       -> 0x01 EXEC_SHELL (走别名映射表)
```

**精确匹配规则仍然有效**：`ps` 必须精确匹配，避免误吞 `psexec` / `psh`。

---

## 9. 服务端 REST API 契约（GUI 依赖）

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/state` | 全量状态（sessions/targets/listeners/jobs），GUI 单次拉取 |
| GET | `/api/sessions` | 会话列表（兼容 v1） |
| GET | `/api/output?sid=&since=` | 会话输出增量 |
| POST | `/api/command` | `{sid, cmd}` 下发命令 |
| POST | `/api/session/sleep` | `{sid, sleep_ms, jitter}` |
| POST | `/api/session/exit` | `{sid}` 结束会话 |
| GET | `/api/credentials` | 凭据库 |
| GET | `/api/downloads` | 下载文件列表 |
| POST | `/api/download/get` | `{sid, path}` 触发下载 |
| GET | `/api/listeners` | Listener 列表 |
| POST | `/api/listener/new` | 新建 listener |
| POST | `/api/listener/del` | 删除 listener |
| GET | `/api/payload/formats` | 可用 payload 格式 |
| POST | `/api/payload/build` | 生成 payload |
| GET | `/api/eventlog` | 事件日志 |
| POST | `/api/login` | `{user, pass}` → token |

所有写操作要求 `Authorization: Bearer <token>`（多用户模式开启时）。

---

## 10. 密钥与配置流转

```
1) 服务器首次启动         → 生成 data/csdev.key + data/csdev.pub
2) 生成器（服务端/客户端）→ 从 data/csdev.key 现算 PUBLICKEYBLOB，连同 host/port/… 一起
                            覆写进载荷配置槽（§1.3），产出载荷
3) 植入体启动             → c2cfg_pubkey() 读槽位公钥（无则回退 pubkey.h）
4) 植入体首次上线         → RSA 加密 (aes_key||hmac_key) 上报
5) 服务端解密并存会话密钥  → 此后全部帧走 AES + HMAC
```

**公钥轮换**：删除 `data/csdev.key` 让服务端首启重生成，或运行 `tools/gen_keypair.ps1 -Force`。
轮换后**重新生成载荷**即可（生成器自动带上新公钥），已上线会话不受影响（密钥已协商）。
手工 gcc 编译的植入体则需重新 `--emit-pubkey` 并重编译。

---

## 11. v1 兼容

| 项 | v1 | v2 |
|---|---|---|
| magic | `KBRK` | `CS2K` |
| 加密 | 固定 RC4 | RSA 交换 + AES/HMAC |
| 路径 | `/report` `/task` `/result` | `/submit`（profile 可覆盖） |
| 载荷 | 纯文本命令 | TLV 任务/结果 |
| 状态 | legacy listener，仅维护不再扩展 | 主线 |

服务端同时监听两套路径；GUI 会话列表对 v1 会话标注 `proto=v1`。

---

## 12. 实现清单（对齐检查）

- [ ] `kits/crypto/aes.c` AES-256-CBC + PKCS#7（含 NIST 向量自测）
- [ ] `kits/crypto/sha256.c` SHA-256（含标准向量自测）
- [ ] `kits/crypto/hmac.c` HMAC-SHA256
- [ ] `kits/crypto/rsa.c` CryptoAPI 封装（导入 PUBLICKEYBLOB、PKCS#1v1.5 加密）
- [ ] `kits/crypto/selftest.c` 向量自检程序（CI 用）
- [ ] `go/proto/crypto.go` 对应解密/校验
- [ ] `go/proto/tlv.go` TLV 编解码
- [ ] `go/proto/frame.go` 帧编解码 + seq 防重放
- [ ] `kits/beacon/beacon2.c` v2 植入体主循环
- [ ] `go/listeners/http.go` v2 listener
- [ ] `tools/e2e_test_v2.ps1` 端到端验证
