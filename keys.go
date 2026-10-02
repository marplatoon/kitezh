package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/flynn/noise"
)

const keySize = 32

func newCipherSuite() noise.CipherSuite {
	return noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b)
}

// читает приватный ключ с диска. Файла нет - создаём
// новый; файл есть, но битый - ошибка, а НЕ тихая перегенерация: потеря
// identity должна быть заметной
func loadOrCreateKeypair(cs noise.CipherSuite, path string) (noise.DHKey, error) {
	priv, err := os.ReadFile(path)
	switch {
	case err == nil:
		return keypairFromPrivate(priv)
	case errors.Is(err, fs.ErrNotExist):
		kp, err := cs.GenerateKeypair(rand.Reader)
		if err != nil {
			return noise.DHKey{}, err
		}
		if err := saveKey(path, kp.Private); err != nil {
			return noise.DHKey{}, err
		}
		return kp, nil
	default:
		return noise.DHKey{}, err
	}
}

// восстанавливает публичный ключ из приватного
func keypairFromPrivate(priv []byte) (noise.DHKey, error) {
	if len(priv) != keySize {
		return noise.DHKey{}, fmt.Errorf("ключ повреждён: %d байт вместо %d", len(priv), keySize)
	}
	k, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return noise.DHKey{}, err
	}
	return noise.DHKey{Private: priv, Public: k.PublicKey().Bytes()}, nil
}

func saveKey(path string, priv []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(priv); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	return f.Close()
}
