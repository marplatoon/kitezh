package main

import (
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/flynn/noise"
)

// runRelay - слушаем и принимаем клиентов. cs и kp нужны только для хендшейка
// клиент<->релей, его делает acceptLoop. С целью релей Noise больше не
// говорит вообще - см. handleRelayPeer
func runRelay(cs noise.CipherSuite, kp noise.DHKey, addr string, allow map[netip.AddrPort]bool) error {
	ln, err := listenUTLS(addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	fmt.Println("Релей слушает на", addr)

	acceptLoop(ln, cs, kp, func(p peer) { handleRelayPeer(p, allow) })
	return nil
}

// handleRelayPeer: ждём CONNECT, открываем только TLS до цели и дальше просто
// гоним байты туда-сюда. Раньше релей сам делал Noise с целью и
// перешифровывал всё - то есть видел весь плейнтекст, чего мы и не хотели.
// Теперь Noise клиент<->цель едет внутри DATA как обычные байты, и
// расшифровать их релей не может - у него нет тех ключей
func handleRelayPeer(p peer, allow map[netip.AddrPort]bool) {
	defer p.conn.Close()

	typ, payload, err := recvCmd(p)
	if err != nil {
		fmt.Println("Релей: ошибка чтения команды:", err)
		return
	}
	if typ != cmdConnect {
		fmt.Println("Релей: ожидали CONNECT, пришло:", typ)
		return
	}
	target := string(payload)
	fmt.Println("Релей: просят подключиться к", target)

	// allow == nil - список не задан, релей открытый (main.go про это предупредил).
	// Иначе пускаем только точное совпадение ip:port из списка
	if allow != nil && !targetAllowed(allow, target) {
		fmt.Println("Релей: цель не в allow-list, отказ:", target)
		sendCmd(p, cmdErr, []byte("цель не разрешена"))
		return
	}

	out, err := dialUTLS(target)
	if err != nil {
		sendCmd(p, cmdErr, []byte(err.Error()))
		return
	}
	defer out.Close()

	if err := sendCmd(p, cmdOK, nil); err != nil {
		return
	}
	fmt.Println("Релей: соединение с", target, "установлено")

	errc := make(chan error, 2)
	go func() { errc <- pipeToTarget(p, out) }()
	go func() { errc <- pipeToClient(out, p) }()

	err = <-errc
	fmt.Println("Релей: закрываем", target, "-", err)
	// deferы закроют оба соединения, и вторая горутина по итогу вылетит с ошибкой чтения
}

// parseAllowList разбирает строку "ip:port,ip:port" из флага -allow.
// Только IP, без доменов: домен релею пришлось бы резолвить самому, а это лишний
// канал для подмены (DNS) и лишний повод для утечки
func parseAllowList(s string) (map[netip.AddrPort]bool, error) {
	allow := make(map[netip.AddrPort]bool)
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		ap, err := netip.ParseAddrPort(item)
		if err != nil {
			return nil, fmt.Errorf("%q: нужен ip:порт, домены нельзя (%v)", item, err)
		}
		allow[netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())] = true
	}
	if len(allow) == 0 {
		return nil, fmt.Errorf("список пустой")
	}
	return allow, nil
}

// targetAllowed: цель от клиента должна разобраться как ip:порт и совпасть
// со списком. Всё, что не разобралось (в том числе домен), - отказ
func targetAllowed(allow map[netip.AddrPort]bool, target string) bool {
	ap, err := netip.ParseAddrPort(target)
	if err != nil {
		return false
	}
	return allow[netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())]
}

// pipeToTarget: DATA от клиента -> достаём байты -> в цель как есть
// вкратце это чужой Noise, внутри фреймы
// со своим префиксом длины, релею туда лезть незачем
func pipeToTarget(from peer, to net.Conn) error {
	for {
		typ, payload, err := recvCmd(from)
		if err != nil {
			return err
		}
		if typ != cmdData {
			return fmt.Errorf("неожиданная команда %d", typ)
		}
		if _, err := to.Write(payload); err != nil {
			return err
		}
		// первые байты в hex - чисто чтобы глазами убедиться, что там каша, а не текст
		fmt.Printf("Релей: клиент -> цель, %d байт, начало: %x\n", len(payload), payload[:min(len(payload), 16)])
	}
}

// pipeToClient: что прочитали из цели -> заворачиваем в DATA -> клиенту.
// Читаем поток кусками, не фреймами: где кончается сообщение, знает только
// клиент, релей этого не видит и не должен
func pipeToClient(from net.Conn, to peer) error {
	buf := make([]byte, maxChunk)
	for {
		n, err := from.Read(buf)
		if n > 0 {
			if err := sendCmd(to, cmdData, buf[:n]); err != nil {
				return err
			}
			fmt.Printf("Релей: цель -> клиент, %d байт, начало: %x\n", n, buf[:min(n, 16)])
		}
		if err != nil {
			return err
		}
	}
}

// runClientViaRelay - режим dial с -relayaddr: идём к target через релей
func runClientViaRelay(cs noise.CipherSuite, kp noise.DHKey, in *bufio.Reader, relayAddr, target string, targetKey []byte) error {
	conn, err := dialUTLS(relayAddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	fmt.Println("Подключился к релею", relayAddr)

	// хендшейк №1: клиент <-> релей, это линк. Ключ релея пока не закрепляем
	// (nil): подмена релея сама по себе ничего не читает, цель защищена своим слоем
	recv, send, err := handshakeClient(conn, cs, kp, nil)
	if err != nil {
		return err
	}
	p := peer{conn: conn, send: send, recv: recv}

	if err := sendCmd(p, cmdConnect, []byte(target)); err != nil {
		return err
	}
	typ, payload, err := recvCmd(p)
	if err != nil {
		return err
	}
	switch typ {
	case cmdOK:
		fmt.Println("Релей подключился к", target)
	case cmdErr:
		return fmt.Errorf("релей не смог подключиться: %s", payload)
	default:
		return fmt.Errorf("неожиданный ответ релея: %d", typ)
	}

	// хендшейк №2: клиент <-> цель, СКВОЗЬ релей. Тут ключ цели ЗАКРЕПЛЯЕМ:
	// именно на этом слое релей мог бы влезть посередине и ответить вместо цели. Дальше все ключи с
	// префиксом e2e - это ключи цели, релей их не знает
	rc := newRelayConn(p)
	e2eRecv, e2eSend, err := handshakeClient(rc, cs, kp, targetKey)
	if err != nil {
		return err
	}
	return runChat(rc, e2eSend, e2eRecv, in)
}
