package main

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"
)

// chainTimeout - сколько даём на построение всей цепочки вместе с хендшейком до цели
// ставим дедлайн на сокет до первого релея, построили - снимаем
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
		fields := strings.Fields(line) // заодно съедает \r от виндятских херопереводов строк
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
