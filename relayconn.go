package main

import (
	"fmt"
	"net"
)

// maxChunk - сколько байт можно запихнуть в один DATA: максимум открытого
// текста минус 1 байт на тип команды
const maxChunk = maxPlaintext - 1

// relayConn - net.Conn, который на самом деле ходит через релей. Снаружи
// это обычное соединение, поэтому handshakeClient и runChat работают с ним
// вообще без изменений - им всё равно, что под капотом

// Write режет данные на куски и отправляет их как DATA по линку с релеем
// (а линк уже зашифрован СВОИМ ключом), Read достаёт DATA обратно. Итого
// Noise клиент<->цель едет ВНУТРИ Noise клиент<->релей, как матрёшка по идее хахах

// Deadline'ы, адреса и Close берутся у настоящего соединения до релея
// (встроенный net.Conn): закрыли relayConn - закрылся линк, релей это
// увидит и закроет своё соединение с целью
type relayConn struct {
	net.Conn      // соединение до релея
	link     peer // оно же + ключи линка, нужны для sendCmd/recvCmd
	buf      []byte
}

func newRelayConn(link peer) *relayConn {
	return &relayConn{Conn: link.conn, link: link}
}

// Read - поток байт, а не сообщения: если в буфере пусто, ждём следующий DATA,
// если приходит больше, чем влезает в b - остаток лежит в buf до следующего
// вызова. readFrame делает ReadFull, так что ему это подходит
func (c *relayConn) Read(b []byte) (int, error) {
	for len(c.buf) == 0 {
		typ, payload, err := recvCmd(c.link)
		if err != nil {
			return 0, err
		}
		if typ != cmdData {
			return 0, fmt.Errorf("неожиданная команда %d", typ)
		}
		c.buf = payload
	}
	n := copy(b, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}

// Write режет на куски по maxChunk. Фрейм внутреннего Noise может быть
// до 65537 байт (2 префикс + 65535), а в один DATA влезает чуть меньше
// без нарезки sendCmd вернул бы errFrameTooLarge на длинных сообщениях
func (c *relayConn) Write(b []byte) (int, error) {
	sent := 0
	for len(b) > 0 {
		n := min(len(b), maxChunk)
		if err := sendCmd(c.link, cmdData, b[:n]); err != nil {
			return sent, err
		}
		sent += n
		b = b[n:]
	}
	return sent, nil
}
