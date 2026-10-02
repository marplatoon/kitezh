package main

import (
	"encoding/binary"
	"errors"
	"io"
)

// aeadOverhead - сколько байт добавляет ChaCha20-Poly1305 к открытому
// тексту (тег аутентификации). Нужен, чтобы заранее знать, влезет ли
// зашифрованное сообщение в один фрейм
const aeadOverhead = 16

// maxFrameSize - предел 2-байтового префикса длины
const maxFrameSize = 65535

// maxPlaintext - самое длинное открытое сообщение, которое после
// шифрования всё ещё поместится в один фрейм
const maxPlaintext = maxFrameSize - aeadOverhead

var errFrameTooLarge = errors.New("сообщение не влезает в один фрейм")

// writeFrame пишет сообщение с 2-байтовым префиксом длины (big-endian).

// Префикс и тело собираются в ОДИН буфер и уходят одним Write: поверх
// TLS каждый Write превращается в отдельную TLS-запись, и два вызова
// подряд давали бы на проводе чередование "2 байта, тело" - готовый
// отпечаток для DPI. Заодно один Write не даст чужим байтам вклиниться
// между префиксом и телом, когда писать в соединение будут несколько
// горутин (релей)
func writeFrame(w io.Writer, msg []byte) error {
	if len(msg) > maxFrameSize {
		return errFrameTooLarge
	}
	buf := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(msg)))
	copy(buf[2:], msg)
	_, err := w.Write(buf)
	return err
}

// readFrame читает ровно один фрейм: сначала длину, потом тело
func readFrame(r io.Reader) ([]byte, error) {
	var length [2]byte
	if _, err := io.ReadFull(r, length[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint16(length[:])
	buf := make([]byte, size)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
