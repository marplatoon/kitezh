package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/hkdf"
)

// тело relay-ячейки ровно cellCap байт:
// [recognized 2][digest 4][cmd 1][stream 2][len 2][данные][нули]
const (
	relHdr = 11
	relCap = cellCap - relHdr
)

// hop - ключи одного хопа. У клиента и у хопа одинаковые, потому
// что оба выводят их из одного значения хендшейка
type hop struct {
	fwd, back *chacha20.Cipher // гамма вперёд (от клиента) и назад
	macKey    [32]byte
}

func newHop(binding []byte) (*hop, error) {
	r := hkdf.New(sha256.New, binding, nil, []byte("kitezh onion v1"))
	var kf, kb [32]byte
	h := &hop{}
	for _, k := range [][]byte{kf[:], kb[:], h.macKey[:]} {
		if _, err := io.ReadFull(r, k); err != nil {
			return nil, err
		}
	}
	nonce := make([]byte, chacha20.NonceSize) // ключи у каждой сессии свои
	var err error
	if h.fwd, err = chacha20.NewUnauthenticatedCipher(kf[:], nonce); err != nil {
		return nil, err
	}
	if h.back, err = chacha20.NewUnauthenticatedCipher(kb[:], nonce); err != nil {
		return nil, err
	}
	return h, nil
}

// digest считается по телу без самого поля digest
func (h *hop) digest(b []byte) [4]byte {
	m, _ := blake2s.New256(h.macKey[:])
	m.Write(b[0:2])
	m.Write(b[6:])
	var d [4]byte
	copy(d[:], m.Sum(nil))
	return d
}

// build собирает открытое тело ячейки для этого хопа, слоёв ещё нет
func (h *hop) build(cmd byte, stream uint16, data []byte) ([]byte, error) {
	if len(data) > relCap {
		return nil, errFrameTooLarge
	}
	b := make([]byte, cellCap) // нули = паддинг и recognized
	b[6] = cmd
	binary.BigEndian.PutUint16(b[7:9], stream)
	binary.BigEndian.PutUint16(b[9:11], uint16(len(data)))
	copy(b[relHdr:], data)
	d := h.digest(b)
	copy(b[2:6], d[:])
	return b, nil
}

// open проверяет, что тело (после снятия слоя) адресовано этому хопу
func (h *hop) open(b []byte) (cmd byte, stream uint16, data []byte, ok bool) {
	if b[0] != 0 || b[1] != 0 {
		return 0, 0, nil, false
	}
	d := h.digest(b)
	if subtle.ConstantTimeCompare(b[2:6], d[:]) != 1 {
		return 0, 0, nil, false
	}
	n := int(binary.BigEndian.Uint16(b[9:11]))
	if n > relCap {
		return 0, 0, nil, false
	}
	return b[6], binary.BigEndian.Uint16(b[7:9]), b[relHdr : relHdr+n], true
}
