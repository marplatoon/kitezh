package main

import (
	"bytes"
	"fmt"
	"net"

	"github.com/flynn/noise"
)

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
func handshakeServer(conn net.Conn, cs noise.CipherSuite, staticKeypair noise.DHKey) (recv, send *noise.CipherState, err error) {
	config := noise.Config{
		CipherSuite:   cs,
		Pattern:       noise.HandshakeXX,
		StaticKeypair: staticKeypair,
		Initiator:     false,
	}

	hs, err := noise.NewHandshakeState(config)
	if err != nil {
		return nil, nil, err
	}

	msg1, err := readFrame(conn)
	if err != nil {
		return nil, nil, err
	}
	if _, _, _, err = hs.ReadMessage(nil, msg1); err != nil {
		return nil, nil, err
	}
	fmt.Println("Получено handshake-сообщение 1 (-> e), байт:", len(msg1))

	msg2, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, nil, err
	}
	if err := writeFrame(conn, msg2); err != nil {
		return nil, nil, err
	}
	fmt.Println("Отправлено handshake-сообщение 2 (<- e, ee, s, es), байт:", len(msg2))

	msg3, err := readFrame(conn)
	if err != nil {
		return nil, nil, err
	}
	_, recvCS, sendCS, err := hs.ReadMessage(nil, msg3)
	if err != nil {
		return nil, nil, err
	}
	fmt.Println("Получено handshake-сообщение 3 (-> s, se), байт:", len(msg3))
	fmt.Println("Handshake завершён, с:", conn.RemoteAddr())

	// recvCS = initiator->responder (расшифровываем то, что шлёт dialer)
	// sendCS = responder->initiator (шифруем то, что шлём мы)
	return recvCS, sendCS, nil
}

// handshakeClient - инициирующая (initiator) сторона того же Noise_XX.
// expectedPeer - закреплённый (pinned) публичный ключ собеседника. nil значит
// "не проверяем", и тогда подменить собеседника может кто угодно на пути:
// XX сам по себе про ключ собеседника заранее ничего не знает
func handshakeClient(conn net.Conn, cs noise.CipherSuite, staticKeypair noise.DHKey, expectedPeer []byte) (recv, send *noise.CipherState, err error) {
	config := noise.Config{
		CipherSuite:   cs,
		Pattern:       noise.HandshakeXX,
		StaticKeypair: staticKeypair,
		Initiator:     true,
	}

	hs, err := noise.NewHandshakeState(config)
	if err != nil {
		return nil, nil, err
	}

	msg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, nil, err
	}
	if err := writeFrame(conn, msg1); err != nil {
		return nil, nil, err
	}
	fmt.Println("Отправлено handshake-сообщение 1 (-> e), байт:", len(msg1))

	msg2, err := readFrame(conn)
	if err != nil {
		return nil, nil, err
	}
	if _, _, _, err = hs.ReadMessage(nil, msg2); err != nil {
		return nil, nil, err
	}
	fmt.Println("Получено handshake-сообщение 2 (<- e, ee, s, es), байт:", len(msg2))

	// сверяем ключ ДО отправки msg3: в нём уезжает НАШ статический ключ, и
	// отдавать его тому, кто подсунул левый ключ (MITM), нельзя. Заодно
	// подделать ответ с настоящим ключом цели не выйдет: без её приватника
	// тег msg2 не сойдётся и ReadMessage выше уже вернул бы ошибку
	if expectedPeer != nil && !bytes.Equal(hs.PeerStatic(), expectedPeer) {
		return nil, nil, fmt.Errorf("ключ собеседника не совпал с закреплённым: пришёл %x, ждали %x", hs.PeerStatic(), expectedPeer)
	}

	msg3, sendCS, recvCS, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, nil, err
	}
	if err := writeFrame(conn, msg3); err != nil {
		return nil, nil, err
	}
	fmt.Println("Отправлено handshake-сообщение 3 (-> s, se), байт:", len(msg3))
	fmt.Println("Handshake завершён")

	// sendCS = initiator->responder (шифруем то, что шлём мы)
	// recvCS = responder->initiator (расшифровываем то, что шлёт listener)
	return recvCS, sendCS, nil
}
