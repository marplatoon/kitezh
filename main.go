package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"strings"
)

func main() {
	mode := flag.String("mode", "listen", "listen, dial или relay")
	keyPath := flag.String("key", "node.key", "путь к файлу с приватным ключом")
	relaysFile := flag.String("relays", "", "только для dial: таблица пиров, строка \"ip:порт ключ\" на пира; хопы цепочки выбираются из неё случайно (-hops)")
	addr := flag.String("addr", "", "ip:порт: для listen/relay адрес прослушивания (по умолчанию :9000), для dial адрес назначения")
	targetKeyHex := flag.String("targetkey", "", "только для dial: публичный ключ цели (hex, строка 'Публичный ключ' у неё в логе); если ключ в хендшейке другой - рвём соединение")
	allowStr := flag.String("allow", "", "только для relay: список целей через запятую (ip:порт,ip:порт), к которым релей вообще согласен подключаться; без флага релей открытый")
	forwardAddr := flag.String("forward", "", "только для listen: ip:порт локального сервиса, куда ведут потоки; без флага потоки выключены")
	localAddr := flag.String("local", "", "только для dial: локальный ip:порт, который становится TCP-потоком через цепочку (127.0.0.1:1080); без флага - чат")
	hopsN := flag.Int("hops", 2, "только для dial: сколько случайных релеев из таблицы брать в цепочку")
	flag.Parse()

	// режим проверяем ДО загрузки ключа: опечатка не должна создавать файл ключа
	switch *mode {
	case "listen", "dial", "relay":
	default:
		fmt.Println("Неправильный режим. Нужно 'listen', 'dial' или 'relay'.")
		return
	}

	if *mode == "dial" && *relaysFile == "" {
		fmt.Println("Режиму dial нужен -relays")
		return
	}

	if *relaysFile != "" && *mode != "dial" {
		fmt.Println("-relays работает только с -mode dial")
		return
	}
	var table []relayHop
	if *relaysFile != "" {
		h, hErr := parseRelaysFile(*relaysFile)
		if hErr != nil {
			fmt.Println("-relays:", hErr)
			return
		}
		table = h
	}

	if *allowStr != "" && *mode != "relay" {
		fmt.Println("-allow работает только с -mode relay")
		return
	}
	var allow map[netip.AddrPort]bool
	if *allowStr != "" {
		a, aErr := parseAllowList(*allowStr)
		if aErr != nil {
			fmt.Println("-allow:", aErr)
			return
		}
		allow = a
	}
	if *mode == "relay" && allow == nil {
		fmt.Println("Внимание: -allow не задан, релей открытый (пустит к любой цели)")
	}

	if *forwardAddr != "" && *mode != "listen" {
		fmt.Println("-forward работает только с -mode listen")
		return
	}
	if *localAddr != "" && *mode != "dial" {
		fmt.Println("-local работает только с -mode dial")
		return
	}

	if *targetKeyHex != "" && *mode != "dial" {
		fmt.Println("-targetkey работает только с -mode dial")
		return
	}
	var targetKey []byte
	if *targetKeyHex != "" {
		k, decErr := hex.DecodeString(strings.TrimSpace(*targetKeyHex))
		if decErr != nil || len(k) != keySize {
			fmt.Println("-targetkey должен быть 64 hex-символа (32 байта), как в строке 'Публичный ключ' у цели")
			return
		}
		targetKey = k
	}
	if *mode == "dial" && targetKey == nil {
		fmt.Println("Режиму dial нужен -targetkey")
		return
	}

	if *addr == "" {
		if *mode == "dial" {
			fmt.Println("Для режима dial нужен -addr ip:порт")
			return
		}
		*addr = ":9000"
	}

	var hops []relayHop
	if *mode == "dial" {
		if *hopsN < 1 {
			fmt.Println("-hops должен быть хотя бы 1")
			return
		}
		h, pErr := pickHops(table, *hopsN, *addr)
		if pErr != nil {
			fmt.Println("-relays:", pErr)
			return
		}
		hops = h
		for i, x := range hops {
			fmt.Printf("Хоп %d выбран: %s\n", i+1, x.addr)
		}
	}

	cs := newCipherSuite()
	staticKeypair, err := loadOrCreateKeypair(cs, *keyPath)
	if err != nil {
		log.Fatal(err)
	}

	if *mode == "relay" {
		fmt.Println("Kitezh релейный узел запущен")
	} else {
		fmt.Println("Kitezh узел запущен, режим:", *mode)
	}

	fmt.Printf("Публичный ключ: %x\n", staticKeypair.Public)

	in := newStdin()
	switch *mode {
	case "listen":
		err = runServer(cs, staticKeypair, in, *addr, *forwardAddr)
	case "dial":
		err = runClient(cs, staticKeypair, in, hops, *addr, targetKey, *localAddr)
	case "relay":
		err = runRelay(cs, staticKeypair, *addr, allow)
	}

	if err != nil {
		log.Fatal(err)
	}
}
