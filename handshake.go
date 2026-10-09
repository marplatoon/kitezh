package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"

	"github.com/flynn/noise"
)

// Границы случайного паддинга (байт) в payload каждого из трёх сообщений Noise_XX
const (
	padMin1, padMax1 = 120, 420  // -> e (открытым текстом)
	padMin2, padMax2 = 300, 1200 // <- e, ee, s, es (зашифрован)
	padMin3, padMax3 = 100, 400  // -> s, se (зашифрован)
)

// randomPad возвращает случайные байты случайной длины из [lo, hi].
// Нули не годятся: msg1 уходит открытым текстом, и ряд нулей виден сразу.
// Случайные байты выглядят так же, как эфемерный ключ рядом с ними
func randomPad(lo, hi int) ([]byte, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(hi-lo+1)))
	if err != nil {
		return nil, err
	}
	b := make([]byte, lo+int(n.Int64()))
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// handshakeServer выполняет ответную (responder) сторону Noise_XX:
//   <- e
//   -> e, ee, s, es
//   <- s, se

// noise.CipherSuite.WriteMessage/ReadMessage на финальном сообщении
// всегда возвращают пару (cs1, cs2) в фиксированном порядке
// "initiator->responder", "responder->initiator" - одинаково на
// обеих сторонах хендшейка. Здесь это сразу превращается в понятные
// recv (расшифровка входящего) / send (шифрование исходящего), чтобы
// вызывающему коду (node.go, chat.go) было всё равно, кто он -
// listener или dialer
func handshakeServer(conn net.Conn, cs noise.CipherSuite, staticKeypair noise.DHKey) (recv, send *noise.CipherState, secret []byte, err error) {
	config := noise.Config{
		CipherSuite:   cs,
		Pattern:       noise.HandshakeXX,
		StaticKeypair: staticKeypair,
		Initiator:     false,
	}

	hs, err := noise.NewHandshakeState(config)
	if err != nil {
		return nil, nil, nil, err
	}

	msg1, err := readFrame(conn)
	if err != nil {
		return nil, nil, nil, err
	}
	if _, _, _, err = hs.ReadMessage(nil, msg1); err != nil {
		return nil, nil, nil, err
	}
	fmt.Println("Получено handshake-сообщение 1 (-> e), байт:", len(msg1))

	pad2, err := randomPad(padMin2, padMax2)
	if err != nil {
		return nil, nil, nil, err
	}
	msg2, _, _, err := hs.WriteMessage(nil, pad2)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := writeFrame(conn, msg2); err != nil {
		return nil, nil, nil, err
	}
	fmt.Println("Отправлено handshake-сообщение 2 (<- e, ee, s, es), байт:", len(msg2))

	msg3, err := readFrame(conn)
	if err != nil {
		return nil, nil, nil, err
	}
	_, recvCS, sendCS, err := hs.ReadMessage(nil, msg3)
	if err != nil {
		return nil, nil, nil, err
	}
	fmt.Println("Получено handshake-сообщение 3 (-> s, se), байт:", len(msg3))
	fmt.Println("Handshake завершён, с:", conn.RemoteAddr())

	// recvCS = initiator->responder (расшифровываем то, что шлёт dialer)
	// sendCS = responder->initiator (шифруем то, что шлём мы)
	return recvCS, sendCS, layerSecret(hs.ChannelBinding(), recvCS, sendCS), nil
}

// handshakeClient - инициирующая (initiator) сторона того же Noise_XX.
// expectedPeer - закреплённый (pinned) публичный ключ собеседника. nil значит
// "не проверяем", и тогда подменить собеседника может кто угодно на пути:
// XX сам по себе про ключ собеседника заранее ничего не знает
func handshakeClient(conn net.Conn, cs noise.CipherSuite, staticKeypair noise.DHKey, expectedPeer []byte) (recv, send *noise.CipherState, secret []byte, err error) {
	config := noise.Config{
		CipherSuite:   cs,
		Pattern:       noise.HandshakeXX,
		StaticKeypair: staticKeypair,
		Initiator:     true,
	}

	hs, err := noise.NewHandshakeState(config)
	if err != nil {
		return nil, nil, nil, err
	}

	pad1, err := randomPad(padMin1, padMax1)
	if err != nil {
		return nil, nil, nil, err
	}
	msg1, _, _, err := hs.WriteMessage(nil, pad1)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := writeFrame(conn, msg1); err != nil {
		return nil, nil, nil, err
	}
	fmt.Println("Отправлено handshake-сообщение 1 (-> e), байт:", len(msg1))

	msg2, err := readFrame(conn)
	if err != nil {
		return nil, nil, nil, err
	}
	if _, _, _, err = hs.ReadMessage(nil, msg2); err != nil {
		return nil, nil, nil, err
	}
	fmt.Println("Получено handshake-сообщение 2 (<- e, ee, s, es), байт:", len(msg2))

	// сверяем ключ ДО отправки msg3: в нём уезжает НАШ статический ключ, и
	// отдавать его тому, кто подсунул левый ключ (MITM), нельзя. Заодно
	// подделать ответ с настоящим ключом цели не выйдет: без её приватника
	// тег msg2 не сойдётся и ReadMessage выше уже вернул бы ошибку
	if expectedPeer != nil && !bytes.Equal(hs.PeerStatic(), expectedPeer) {
		return nil, nil, nil, fmt.Errorf("ключ собеседника не совпал с закреплённым: пришёл %x, ждали %x", hs.PeerStatic(), expectedPeer)
	}

	pad3, err := randomPad(padMin3, padMax3)
	if err != nil {
		return nil, nil, nil, err
	}
	msg3, sendCS, recvCS, err := hs.WriteMessage(nil, pad3)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := writeFrame(conn, msg3); err != nil {
		return nil, nil, nil, err
	}
	fmt.Println("Отправлено handshake-сообщение 3 (-> s, se), байт:", len(msg3))
	fmt.Println("Handshake завершён")

	// sendCS = initiator->responder (шифруем то, что шлём мы)
	// recvCS = responder->initiator (расшифровываем то, что шлёт listener)
	return recvCS, sendCS, layerSecret(hs.ChannelBinding(), sendCS, recvCS), nil
}

// layerSecret - материал для ключей onion-слоя. Хеш хендшейка публичный
// (его видно по трафику), секретность даёт транспортный ключ. Порядок
// фиксирован (i->r, потом r->i), чтобы обе стороны получили одно и то же
func layerSecret(h []byte, ir, ri *noise.CipherState) []byte {
	kir, kri := ir.UnsafeKey(), ri.UnsafeKey()
	out := append([]byte{}, h...)
	out = append(out, kir[:]...)
	return append(out, kri[:]...)
}
