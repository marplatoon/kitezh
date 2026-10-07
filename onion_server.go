package main

import (
	"bufio"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/flynn/noise"
)

// runServer - режим listen: цель сама последний хоп цепочки.
// Чатимся с тем, чья цепочка первой прислала DATA; остальные игнорируем
func runServer(cs noise.CipherSuite, kp noise.DHKey, in *bufio.Reader, addr, forward string) error {
	ln, err := listenUTLS(addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	fmt.Println("Слушаем на", addr, "ждём цепочку...")

	var active atomic.Pointer[circuit]
	done := make(chan struct{})
	var once sync.Once

	cfg := circuitCfg{cs: cs, kp: kp, forward: forward}
	cfg.onData = func(c *circuit, data []byte) {
		if active.CompareAndSwap(nil, c) {
			go sendLines(c, in)
		} else if active.Load() != c {
			return // занято другим собеседником
		}
		fmt.Println("\nСобеседник:", string(data))
		fmt.Print("Введите сообщение: ")
	}

	go acceptLoop(ln, cs, kp, func(p peer) {
		c := handleCircuit(p, cfg)
		if c != nil && active.Load() == c {
			once.Do(func() { close(done) })
		}
	})

	<-done
	fmt.Println("Собеседник ушёл")
	return nil
}

// sendLines: строки со stdin уходят в цепочку ответной ячейкой
func sendLines(c *circuit, in *bufio.Reader) {
	for {
		fmt.Print("Введите сообщение: ")
		text, err := in.ReadString('\n')
		if err != nil {
			return
		}
		text = strings.TrimRight(text, "\r\n")
		if len(text) > relCap {
			fmt.Printf("Слишком длинное сообщение (%d байт, максимум %d)\n", len(text), relCap)
			continue
		}
		if err := c.reply(rcData, 0, []byte(text)); err != nil {
			return
		}
	}
}
