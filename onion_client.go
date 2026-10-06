package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/flynn/noise"
)

// clientCircuit - цепочка глазами клиента: линк до первого хопа
// и ключи каждого хопа по порядку
type clientCircuit struct {
	link peer
	hops []*hop
}

// sendTo шлёт ячейку хопу k: слои накладываем от k до первого
func (c *clientCircuit) sendTo(k int, cmd byte, data []byte) error {
	b, err := c.hops[k].build(cmd, data)
	if err != nil {
		return err
	}
	for i := k; i >= 0; i-- {
		c.hops[i].fwd.XORKeyStream(b, b)
	}
	return sendCmd(c.link, cmdRelay, b)
}

// recv читает ячейку и снимает слои, пока кто-то из хопов её не узнает
func (c *clientCircuit) recv() (from int, cmd byte, data []byte, err error) {
	typ, b, err := recvCmd(c.link)
	if err != nil {
		return 0, 0, nil, err
	}
	if typ != cmdRelay || len(b) != cellCap {
		return 0, 0, nil, errors.New("плохая ячейка")
	}
	for i, h := range c.hops {
		h.back.XORKeyStream(b, b)
		if cmd, data, ok := h.open(b); ok {
			return i, cmd, data, nil
		}
	}
	return 0, 0, nil, errors.New("ячейку не узнал ни один хоп")
}

// extend продлевает цепочку от последнего хопа до addr (ключ key закреплён)
func (c *clientCircuit) extend(cs noise.CipherSuite, addr string, key []byte) error {
	init, msg1, err := hopStart(cs, key)
	if err != nil {
		return err
	}
	ext, err := buildExtend(addr, key, msg1)
	if err != nil {
		return err
	}
	last := len(c.hops) - 1
	if err := c.sendTo(last, rcExtend, ext); err != nil {
		return err
	}
	from, cmd, data, err := c.recv()
	if err != nil {
		return err
	}
	if from != last {
		return errors.New("ответ на EXTEND пришёл не от того хопа")
	}
	switch cmd {
	case rcExtended:
		h, err := init.finish(data)
		if err != nil {
			return fmt.Errorf("хендшейк хопа: %w", err)
		}
		c.hops = append(c.hops, h)
		return nil
	case rcError:
		return fmt.Errorf("хоп отказал: %s", data)
	}
	return fmt.Errorf("неожиданный ответ %d", cmd)
}

// buildCircuit строит цепочку: релеи по порядку, последним хопом - цель.
// Закрыть соединение (c.link.conn) должен вызывающий
func buildCircuit(cs noise.CipherSuite, kp noise.DHKey, hops []relayHop, target string, targetKey []byte) (*clientCircuit, error) {
	if targetKey == nil {
		return nil, errors.New("нужен -targetkey (ключ цели закрепляется в хендшейке хопа)")
	}
	conn, err := dialUTLS(hops[0].addr)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(chainTimeout))
	fmt.Println("Подключился к релею 1:", hops[0].addr)

	c, err := openCircuit(cs, kp, conn, hops, target, targetKey)
	if err != nil {
		conn.Close()
		return nil, err
	}
	conn.SetDeadline(time.Time{})
	return c, nil
}

func openCircuit(cs noise.CipherSuite, kp noise.DHKey, conn net.Conn, hops []relayHop, target string, targetKey []byte) (*clientCircuit, error) {
	recv, send, secret, err := handshakeClient(conn, cs, kp, hops[0].key)
	if err != nil {
		return nil, fmt.Errorf("хендшейк с релеем 1: %w", err)
	}
	c := &clientCircuit{link: peer{conn: conn, send: send, recv: recv, secret: secret}}

	// первый хоп: ключи из самого линка
	if err := sendCmd(c.link, cmdCreateFast, nil); err != nil {
		return nil, err
	}
	typ, _, err := recvCmd(c.link)
	if err != nil || typ != cmdCreated {
		return nil, fmt.Errorf("релей 1 не создал цепочку: typ=%d err=%v", typ, err)
	}
	h1, err := newHop(secret)
	if err != nil {
		return nil, err
	}
	c.hops = []*hop{h1}

	for i := 1; i < len(hops); i++ {
		if err := c.extend(cs, hops[i].addr, hops[i].key); err != nil {
			return nil, fmt.Errorf("продление до релея %d: %w", i+1, err)
		}
		fmt.Printf("Релей %d (%s) в цепочке\n", i+1, hops[i].addr)
	}
	if err := c.extend(cs, target, targetKey); err != nil {
		return nil, fmt.Errorf("продление до цели: %w", err)
	}
	fmt.Println("Цепочка до цели построена")
	return c, nil
}

// runClient - режим dial: строим цепочку и болтаем с целью
func runClient(cs noise.CipherSuite, kp noise.DHKey, in *bufio.Reader, hops []relayHop, target string, targetKey []byte) error {
	c, err := buildCircuit(cs, kp, hops, target, targetKey)
	if err != nil {
		return err
	}
	defer c.link.conn.Close()
	return c.chat(in)
}

func keepGap() time.Duration {
	return 20*time.Second + time.Duration(rand.Int63n(int64(20*time.Second)))
}

// chat: строки с stdin уходят DATA-ячейками последнему хопу (цели),
// ответы цели печатаем
func (c *clientCircuit) chat(in *bufio.Reader) error {
	last := len(c.hops) - 1
	netDone := make(chan error, 1)
	go func() { netDone <- c.readLoop(last) }()

	lines := make(chan string)
	inErr := make(chan error, 1)
	go func() {
		for {
			text, err := in.ReadString('\n')
			if err != nil {
				inErr <- err
				return
			}
			lines <- strings.TrimRight(text, "\r\n")
		}
	}()

	keep := time.NewTimer(keepGap())
	defer keep.Stop()
	showPrompt := true

	for {
		if showPrompt {
			fmt.Print("Введите сообщение: ")
		}
		showPrompt = true
		select {
		case text := <-lines:
			if len(text) > relCap {
				fmt.Printf("Слишком длинное сообщение (%d байт, максимум %d)\n", len(text), relCap)
				continue
			}
			if err := c.sendTo(last, rcData, []byte(text)); err != nil {
				return err
			}
			keep.Reset(keepGap())
		case <-keep.C:
			if err := c.sendTo(last, rcDrop, nil); err != nil {
				return err
			}
			keep.Reset(keepGap())
			showPrompt = false
		case err := <-netDone:
			return err
		case err := <-inErr:
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func (c *clientCircuit) readLoop(last int) error {
	for {
		from, cmd, data, err := c.recv()
		if err != nil {
			fmt.Println("\nСоединение закрыто:", err)
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if from != last || cmd != rcData {
			continue
		}
		fmt.Println("\nСобеседник:", string(data))
		fmt.Print("Введите сообщение: ")
	}
}
