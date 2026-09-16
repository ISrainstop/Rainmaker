package main

import (
	"testing"

	"golang.org/x/text/encoding/simplifiedchinese"
)

// TestEnsureUTF8 中文 Windows 的 shell 输出是 GBK, 直接按 UTF-8 显示会变乱码。
// 结果通道只承载文本(二进制走 TLV 分块通道), 所以按 GB18030 兜底解码。
func TestEnsureUTF8(t *testing.T) {
	// 用编码器现造 GBK 字节, 避免手写字节序列写错
	gbk, err := simplifiedchinese.GBK.NewEncoder().Bytes([]byte("用户信息 管理员"))
	if err != nil {
		t.Fatalf("构造 GBK 样本失败: %v", err)
	}
	if got := string(ensureUTF8(gbk)); got != "用户信息 管理员" {
		t.Fatalf("GBK 应被解码为 UTF-8, 实得 %q", got)
	}

	// 本来就是 UTF-8 -> 原样返回(不重复转码)
	utf := []byte("正常 UTF-8：中文与 ASCII mixed")
	if got := string(ensureUTF8(utf)); got != string(utf) {
		t.Fatalf("合法 UTF-8 不应被改动, 实得 %q", got)
	}

	// 空输入
	if len(ensureUTF8(nil)) != 0 {
		t.Fatal("nil 应返回空")
	}

	// 纯 ASCII
	if got := string(ensureUTF8([]byte("plain ascii"))); got != "plain ascii" {
		t.Fatalf("ASCII 不应被改动, 实得 %q", got)
	}
}
