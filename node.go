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
}

// runServer - режим чата: ждём первого пира, прошедшего хендшейк.
// Что делать с пиром после хендшейка, решает onPeer, поэтому политика
// "первый выигрывает" живёт здесь, а не в общем коде приёма
func runServer(cs noise.CipherSuite, staticKeypair noise.DHKey, in *bufio.Reader, addr string) error {
	ln, err := listenUTLS(addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	fmt.Println("Слушаем на", addr, ", ждём соединения...")

	// буфер 1: победитель кладёт пира, не дожидаясь, пока main дойдёт до чтения из канала
	ready := make(chan peer, 1)
	go acceptLoop(ln, cs, staticKeypair, func(p peer) {
		select {
		case ready <- p:
		default:
			fmt.Println("Пир уже подключён, отбрасываем:", p.conn.RemoteAddr())
			p.conn.Close()
		}
	})

	p := <-ready
	defer p.conn.Close()
	return runChat(p.conn, p.send, p.recv, in)
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

	recv, send, err := handshakeServer(conn, cs, kp)
	if err != nil {
		fmt.Println("Хендшейк не прошёл (не наш протокол?):", err)
		conn.Close()
		return
	}
	conn.SetDeadline(time.Time{}) // хендшейк наш - дальше дедлайн снимаем

	// onPeer блокирующий: для релейки он живёт столько же, сколько пир
	onPeer(peer{conn: conn, send: send, recv: recv})
}

// runClient проводит соединение через handshake + chat. targetKey - закреплённый
// ключ собеседника (nil - не проверяем)
func runClient(cs noise.CipherSuite, staticKeypair noise.DHKey, in *bufio.Reader, addr string, targetKey []byte) error {
	conn, err := dialUTLS(addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	fmt.Println("Подключился к", addr)

	recv, send, err := handshakeClient(conn, cs, staticKeypair, targetKey)
	if err != nil {
		return err
	}

	return runChat(conn, send, recv, in)
}

// newStdin - единственный буферизованный reader на stdin
func newStdin() *bufio.Reader { return bufio.NewReader(os.Stdin) }
