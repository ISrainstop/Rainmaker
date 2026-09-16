package main

import "testing"

// TestV2RouteNativeOps 原生横向移动命令必须路由到 CMD_NET_OPS 且 op 前缀正确。
//
// 起因: `wmiexec` 这个名字在 v1 别名层已被占用(wmic.exe shell 组合),
// 原生实现走 `wmiexec2`。这里把"名字 -> 类别 -> op 前缀"三者钉住,
// 避免以后有人把 wmiexec2 挪回 wmiexec 而静默退化成老路径。
func TestV2RouteNativeOps(t *testing.T) {
	cases := []struct {
		cmd       string
		wantClass byte
		wantOp    string
	}{
		{"psexec2 10.0.0.5 whoami", cmdNetOps, "psexec 10.0.0.5 whoami"},
		{"psexec-native 10.0.0.5 whoami", cmdNetOps, "psexec 10.0.0.5 whoami"},
		{`wmiexec2 10.0.0.5 whoami`, cmdNetOps, "wmiexec 10.0.0.5 whoami"},
		{`wmiexec2 -u admin -p p@ss -d CORP 10.0.0.5 ipconfig /all`, cmdNetOps,
			"wmiexec -u admin -p p@ss -d CORP 10.0.0.5 ipconfig /all"},
		{"wmiexec-native 10.0.0.5 whoami", cmdNetOps, "wmiexec 10.0.0.5 whoami"},
	}
	for _, c := range cases {
		class, _, arg := v2Route(c.cmd)
		if class != c.wantClass {
			t.Errorf("v2Route(%q) class=0x%02x, 期望 0x%02x", c.cmd, class, c.wantClass)
			continue
		}
		if got := string(arg); got != c.wantOp {
			t.Errorf("v2Route(%q) op=%q, 期望 %q", c.cmd, got, c.wantOp)
		}
	}
}

// TestV2RouteWmiexecAliasUntouched 别名层的 wmiexec 仍然是 shell 组合老路径
// (走 mapCommand 而非 CMD_NET_OPS) —— 这条差异是刻意的, 别"顺手统一"掉。
func TestV2RouteWmiexecAliasUntouched(t *testing.T) {
	class, _, _ := v2Route("wmiexec 10.0.0.5 whoami")
	if class == cmdNetOps {
		t.Fatal("`wmiexec` 不应路由到原生 CMD_NET_OPS(那是 wmiexec2 的名字), " +
			"否则 v1 别名层的 wmic.exe 组合路径会被静默替换")
	}
	if !containsSub(string(mapCommand("wmiexec 10.0.0.5 whoami")), "wmic") {
		t.Fatal("别名层 `wmiexec` 应仍然映射到 wmic.exe 组合命令")
	}
}

func containsSub(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
