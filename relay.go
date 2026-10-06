package main

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/flynn/noise"
)

// connectTimeout - сколько даём клиенту на CONNECT после хендшейка.
// Молчун иначе держал бы нам горутину и сокет вечно
const connectTimeout = 10 * time.Second

// relayIdleTimeout - сколько цепочка может молчать, прежде чем релей её закроет.
// Клиент в onion-режиме шлёт keepalive раз в 20-40с, так что живой чат не умирает
const relayIdleTimeout = 5 * time.Minute

// runRelay - слушаем и принимаем клиентов. Хендшейк с линком делает acceptLoop,
// дальше пира ведёт handleCircuit
func runRelay(cs noise.CipherSuite, kp noise.DHKey, addr string, allow map[netip.AddrPort]bool) error {
	ln, err := listenUTLS(addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	fmt.Println("Релей слушает на", addr)

	acceptLoop(ln, cs, kp, func(p peer) {
		handleCircuit(p, circuitCfg{cs: cs, kp: kp, allow: allow})
	})
	return nil
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
