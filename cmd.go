package main

import "errors"

// тип команды - первый байт внутри зашифрованного фрейма
const (
	cmdConnect byte = 1 // адрес назначения "ip:порт"
	cmdOK      byte = 2
	cmdErr     byte = 3 // текст ошибки
	cmdData    byte = 4 // данные
)

// sendCmd шифрует [тип|payload] ключом линка и пишет одним фреймом
func sendCmd(p peer, typ byte, payload []byte) error {
	msg := append([]byte{typ}, payload...)
	// длину проверяем до Encrypt
	if len(msg) > maxPlaintext {
		return errFrameTooLarge
	}
	ct, err := p.send.Encrypt(nil, nil, msg)
	if err != nil {
		return err
	}
	return writeFrame(p.conn, ct)
}

// recvCmd читает фрейм, расшифровывает и отделяет байт типа
func recvCmd(p peer) (byte, []byte, error) {
	ct, err := readFrame(p.conn)
	if err != nil {
		return 0, nil, err
	}
	pt, err := p.recv.Decrypt(nil, nil, ct)
	if err != nil {
		return 0, nil, err
	}
	if len(pt) == 0 {
		return 0, nil, errors.New("пустая команда")
	}
	return pt[0], pt[1:], nil
}
