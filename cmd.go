package main

import (
	"encoding/binary"
	"errors"
	"io"
)

// тип команды - первый байт внутри зашифрованной ячейки
const (
	cmdConnect byte = 1 // адрес назначения "ip:порт"
	cmdOK      byte = 2
	cmdErr     byte = 3 // текст ошибки
	cmdData    byte = 4 // данные

	cmdCreate     byte = 5 // msg1 хендшейка хопа
	cmdCreated    byte = 6 // msg2 (для CREATE_FAST пусто)
	cmdCreateFast byte = 7 // ключи хопа берём из самого линка
	cmdRelay      byte = 8 // relay-ячейка, тело ровно cellCap
)

// sendCmd кладёт [тип|длина|данные|нули] в ячейку, шифрует ключом линка
// и пишет одним Write (одна TLS-запись)
func sendCmd(p peer, typ byte, payload []byte) error {
	// длину проверяем до Encrypt, иначе счётчик nonce уедет впустую
	if len(payload) > cellCap {
		return errFrameTooLarge
	}
	msg := make([]byte, cellPlain) // нули = паддинг
	msg[0] = typ
	binary.BigEndian.PutUint16(msg[1:cellHdr], uint16(len(payload)))
	copy(msg[cellHdr:], payload)

	ct, err := p.send.Encrypt(nil, nil, msg)
	if err != nil {
		return err
	}
	_, err = p.conn.Write(ct)
	return err
}

// recvCmd читает ровно одну ячейку, расшифровывает и достаёт тип и данные
func recvCmd(p peer) (byte, []byte, error) {
	ct := make([]byte, cellSize)
	if _, err := io.ReadFull(p.conn, ct); err != nil {
		return 0, nil, err
	}
	pt, err := p.recv.Decrypt(nil, nil, ct)
	if err != nil {
		return 0, nil, err
	}
	// длина лежит внутри шифртекста, так что проверяем уже после Decrypt
	n := int(binary.BigEndian.Uint16(pt[1:cellHdr]))
	if n > cellCap {
		return 0, nil, errors.New("битая длина в ячейке")
	}
	return pt[0], pt[cellHdr : cellHdr+n], nil
}
