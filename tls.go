package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
)

// dialTimeout - сколько ждём TCP + TLS до собеседника. Не ответил - считаем недоступным
const dialTimeout = 10 * time.Second

// generateSelfSignedCert создаёт эфемерный сертификат прямо в памяти,
// без диска и без CA. Живёт один запуск процесса - тот же паттерн
// упрощения, что уже есть у статического Noise-ключа в keys.go
// (тоже регенерируется каждый раз, это известный и принятый пробел
// на текущей стадии)
func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}

// listenUTLS - обычный crypto/tls-listener. Серверную сторону DPI
// фингерпринтить особо нечего, смотрят в первую очередь на ClientHello
// камуфляж сервера (домен-фронтинг и т.п.) - отдельная задача позже
func listenUTLS(addr string) (net.Listener, error) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}
	return tls.Listen("tcp", addr, cfg)
}

// dialUTLS - TCP + TLS-хендшейк с ClientHello, побайтово имитирующим
// реальный браузер. Для DPI это выглядит как рядовой HTTPS, а не как
// самодельный golang-TLS-стек
func dialUTLS(addr string) (net.Conn, error) {
	rawConn, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return nil, err
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		rawConn.Close()
		return nil, err
	}

	cfg := &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	}

	// DialTimeout покрывает только TCP, а TLS-хендшейк с молчащим сервером
	// висел бы вечно - поэтому на него отдельный дедлайн, после хендшейка снимаем
	rawConn.SetDeadline(time.Now().Add(dialTimeout))
	uConn := utls.UClient(rawConn, cfg, utls.HelloChrome_Auto)
	if err := uConn.Handshake(); err != nil {
		rawConn.Close()
		return nil, err
	}
	rawConn.SetDeadline(time.Time{})
	return uConn, nil
}
