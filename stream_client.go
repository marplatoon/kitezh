package main

import (
	"errors"
	"fmt"
	"net"
	"time"
)

// поток глазами клиента: локальный сокет и ответ на BEGIN
type clientStream struct {
	conn  net.Conn
	ready chan error // nil = цель подключилась, иначе причина отказа
}

// addStream выдаёт номер потока. Счётчик просто растёт, 0 пропускаем (это чат)
func (c *clientCircuit) addStream(conn net.Conn) (uint16, *clientStream) {
	c.smu.Lock()
	defer c.smu.Unlock()
	if len(c.streams) >= maxStreams {
		return 0, nil
	}
	if c.streams == nil {
		c.streams = map[uint16]*clientStream{}
	}
	for {
		c.nextID++
		if c.nextID == 0 {
			continue
		}
		if _, busy := c.streams[c.nextID]; !busy {
			break
		}
	}
	s := &clientStream{conn: conn, ready: make(chan error, 1)}
	c.streams[c.nextID] = s
	return c.nextID, s
}

func (c *clientCircuit) getStream(id uint16) *clientStream {
	c.smu.Lock()
	defer c.smu.Unlock()
	return c.streams[id]
}

// dropStream закрывает поток и говорит, был ли он. END шлём только если был
func (c *clientCircuit) dropStream(id uint16) bool {
	c.smu.Lock()
	s, ok := c.streams[id]
	delete(c.streams, id)
	c.smu.Unlock()
	if ok {
		s.conn.Close()
	}
	return ok
}

// openStream: одно локальное соединение = один поток
func (c *clientCircuit) openStream(last int, conn net.Conn) {
	id, s := c.addStream(conn)
	if s == nil {
		fmt.Println("Слишком много потоков, соединение отброшено")
		conn.Close()
		return
	}
	if err := c.sendTo(last, rcBegin, id, nil); err != nil {
		c.dropStream(id)
		return
	}
	select {
	case err := <-s.ready:
		if err != nil {
			fmt.Println("Поток", id, "отказ:", err)
			c.dropStream(id)
			return
		}
	case <-time.After(connectTimeout):
		fmt.Println("Поток", id, "цель не ответила")
		if c.dropStream(id) {
			c.sendTo(last, rcEnd, id, nil)
		}
		return
	}

	// пока не пришёл CONNECTED, из сокета ничего не читаем и не шлём
	buf := make([]byte, relCap)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			if c.sendTo(last, rcData, id, buf[:n]) != nil {
				c.dropStream(id)
				return
			}
		}
		if err != nil {
			if c.dropStream(id) {
				c.sendTo(last, rcEnd, id, nil)
			}
			return
		}
	}
}

// streamLoop - единственный, кто читает ячейки от цели, раскладывает по потокам
func (c *clientCircuit) streamLoop(last int) error {
	for {
		from, cmd, stream, data, err := c.recv()
		if err != nil {
			return err
		}
		if from != last || stream == 0 {
			continue
		}
		s := c.getStream(stream)
		if s == nil {
			continue
		}
		switch cmd {
		case rcConnected:
			select {
			case s.ready <- nil:
			default:
			}
		case rcData:
			if _, err := s.conn.Write(data); err != nil {
				if c.dropStream(stream) {
					c.sendTo(last, rcEnd, stream, nil)
				}
			}
		case rcEnd:
			select {
			case s.ready <- errors.New(string(data)):
			default:
			}
			c.dropStream(stream)
		}
	}
}

// forward - режим dial -local: слушаем локальный порт и гоним его в цепочку
func (c *clientCircuit) forward(local string) error {
	ln, err := net.Listen("tcp", local)
	if err != nil {
		return err
	}
	defer ln.Close()
	fmt.Println("Слушаем локально на", local)

	last := len(c.hops) - 1
	netDone := make(chan error, 1)
	go func() { netDone <- c.streamLoop(last) }()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go c.openStream(last, conn)
		}
	}()

	keep := time.NewTimer(keepGap())
	defer keep.Stop()
	for {
		select {
		case <-keep.C:
			if err := c.sendTo(last, rcDrop, 0, nil); err != nil {
				return err
			}
			keep.Reset(keepGap())
		case err := <-netDone:
			return err
		}
	}
}
