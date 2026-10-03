package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/flynn/noise"
)

// chainTimeout - сколько даём на построение всей цепочки вместе с хендшейком до цели
// ставим дедлайн на настоящий сокет до первого релея: все вложенные слои читают
// через него, так что один дедлайн покрывает всё. Построили - снимаем
const chainTimeout = 30 * time.Second

// relayHop - один релей в цепочке клиента. Ключ обязателен: именно по нему
// мы узнаём, что на том конце тот релей, а не подмена
type relayHop struct {
	addr string
	key  []byte
}

// parseRelaysFile читает файл со списком релеев: по строке "ip:порт hex-ключ",
// порядок строк = порядок хопов (первая строка - ближайший к клиенту). Пустые
// строки и всё после # пропускаем. Домены нельзя - по той же причине,
// что и в -allow. Строка без ключа - ошибка, а не молчаливое "не проверяем":
// без закрепления ключа промежуточный релей может ответить вместо следующего
func parseRelaysFile(path string) ([]relayHop, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// ебучи блокнот на винде любит добавлять BOM в начало файла / спасибо ИИ что нашёл эту ошибку ибо не доходило в чем дело когда тестыыыбыли
	text := strings.TrimPrefix(string(data), "\ufeff")

	var hops []relayHop
	for i, line := range strings.Split(text, "\n") {
		n := i + 1
		if j := strings.IndexByte(line, '#'); j >= 0 {
			line = line[:j]
		}
		fields := strings.Fields(line) // заодно съедает \r от Windows-переводов строк
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 2 {
			return nil, fmt.Errorf("%s, строка %d: нужно 'ip:порт ключ', а полей %d", path, n, len(fields))
		}
		ap, err := netip.ParseAddrPort(fields[0])
		if err != nil {
			return nil, fmt.Errorf("%s, строка %d: %q: нужен ip:порт, домены нельзя (%v)", path, n, fields[0], err)
		}
		key, err := hex.DecodeString(fields[1])
		if err != nil || len(key) != keySize {
			return nil, fmt.Errorf("%s, строка %d: ключ должен быть 64 hex-символа (32 байта)", path, n)
		}
		hops = append(hops, relayHop{addr: ap.String(), key: key})
	}
	if len(hops) == 0 {
		return nil, fmt.Errorf("%s: ни одного релея", path)
	}
	return hops, nil
}

// connectVia просит релей на конце link открыть соединение до target и ждёт OK
// link может быть и настоящим сокетом, и relayConn - sendCmd/recvCmd всё равно
func connectVia(link peer, target string) error {
	if err := sendCmd(link, cmdConnect, []byte(target)); err != nil {
		return err
	}
	typ, payload, err := recvCmd(link)
	if err != nil {
		return err
	}
	switch typ {
	case cmdOK:
		return nil
	case cmdErr:
		return fmt.Errorf("релей не смог подключиться к %s: %s", target, payload)
	default:
		return fmt.Errorf("неожиданный ответ релея: %d", typ)
	}
}

// runClientViaChain строит цепочку релеев слой за слоем (телескопом) и в конце
// говорит с целью. Релеям ничего не надо знать друг о друге: каждый видит только
// просьбу "соедини меня с X" и гонит байты. Весь маршрут знает один клиент.

// Каждая итерация цикла: просим текущий конец цепочки открыть соединение до
// следующего релея, оборачиваем это в relayConn и делаем с следующим релеем
// Noise СКВОЗЬ уже построенные слои. Получается новый link, на один хоп длиннее
func runClientViaChain(cs noise.CipherSuite, kp noise.DHKey, in *bufio.Reader, hops []relayHop, target string, targetKey []byte) error {
	conn, err := dialUTLS(hops[0].addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(chainTimeout))
	fmt.Println("Подключился к релею 1:", hops[0].addr)

	// слой 1: клиент <-> первый релей, по настоящему сокету
	recv, send, err := handshakeClient(conn, cs, kp, hops[0].key)
	if err != nil {
		return fmt.Errorf("хендшейк с релеем 1: %w", err)
	}
	link := peer{conn: conn, send: send, recv: recv}

	// слои 2..N: каждый следующий релей достаём через предыдущие
	for i := 1; i < len(hops); i++ {
		if err := connectVia(link, hops[i].addr); err != nil {
			return fmt.Errorf("релей %d -> релей %d: %w", i, i+1, err)
		}
		rc := newRelayConn(link)
		recv, send, err = handshakeClient(rc, cs, kp, hops[i].key)
		if err != nil {
			return fmt.Errorf("хендшейк с релеем %d: %w", i+1, err)
		}
		link = peer{conn: rc, send: send, recv: recv}
		fmt.Printf("Релей %d (%s) в цепочке\n", i+1, hops[i].addr)
	}

	// последний слой: клиент <-> цель, сквозь всю цепочку
	if err := connectVia(link, target); err != nil {
		return fmt.Errorf("последний релей -> цель: %w", err)
	}
	fmt.Println("Последний релей подключился к", target)
	rc := newRelayConn(link)
	e2eRecv, e2eSend, err := handshakeClient(rc, cs, kp, targetKey)
	if err != nil {
		return fmt.Errorf("хендшейк с целью: %w", err)
	}

	conn.SetDeadline(time.Time{}) // цепочка построена, дальше дедлайны ставят релеи
	return runChat(rc, e2eSend, e2eRecv, in)
}
