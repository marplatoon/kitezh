package main

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/flynn/noise"
)

// handshakeTimeout - сколько даём собеседнику на TLS + Noise_XX. Кто не уложился - не наш узел
const handshakeTimeout = 5 * time.Second

// peer - соединение, уже прошедшее хендшейк, вместе с ключами
type peer struct {
	conn       net.Conn
	send, recv *noise.CipherState
	secret     []byte // материал для ключей слоя (из хендшейка линка)
}

// acceptLoop принимает соединения, пока listener не закроют. Каждое соединение обрабатывается в своей горутине
func acceptLoop(ln net.Listener, cs noise.CipherSuite, kp noise.DHKey, onPeer func(peer)) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			fmt.Println("Ошибка accept:", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		fmt.Println("Подключение принято от:", conn.RemoteAddr())
		go serveConn(conn, cs, kp, onPeer)
	}
}

// serveConn прогоняет одно входящее соединение через хендшейк и отдаёт
// готового пира в onPeer. Всё, что не говорит на нашем протоколе, просто отбрасывается
func serveConn(conn net.Conn, cs noise.CipherSuite, kp noise.DHKey, onPeer func(peer)) {
	// дедлайн только на этап хендшейка. TLS-хендшейк у crypto/tls ленивый
	// и случается внутри первого чтения, так что дедлайн покрывает и его
	conn.SetDeadline(time.Now().Add(handshakeTimeout))

	recv, send, secret, err := handshakeServer(conn, cs, kp)
	if err != nil {
		fmt.Println("Хендшейк не прошёл (не наш протокол?):", err)
		conn.Close()
		return
	}
	conn.SetDeadline(time.Time{}) // хендшейк наш - дальше дедлайн снимаем

	// onPeer блокирующий: для релейки он живёт столько же, сколько пир
	onPeer(peer{conn: conn, send: send, recv: recv, secret: secret})
}

// newStdin - единственный буферизованный reader на stdin
func newStdin() *bufio.Reader { return bufio.NewReader(os.Stdin) }
