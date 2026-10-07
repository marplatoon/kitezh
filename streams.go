package main

import (
	"errors"
	"fmt"
	"net"
)

// максимум потоков на одну цепочку, дальше BEGIN отбиваем
const maxStreams = 64

// beginStream: клиент просит поток. Адрес он не задаёт, цель берём из -forward
func (c *circuit) beginStream(id uint16) error {
	if c.cfg.forward == "" {
		return c.reply(rcEnd, id, []byte("потоки выключены"))
	}
	if id == 0 {
		return errors.New("BEGIN с потоком 0")
	}
	c.smu.Lock()
	_, dup := c.streams[id]
	full := len(c.streams) >= maxStreams
	c.smu.Unlock()
	if dup {
		return errors.New("такой поток уже есть")
	}
	if full {
		return c.reply(rcEnd, id, []byte("слишком много потоков"))
	}
	// dial стоит в цикле цепочки, для локального адреса это мгновенно
	conn, err := net.DialTimeout("tcp", c.cfg.forward, connectTimeout)
	if err != nil {
		fmt.Println("Поток", id, "не открылся:", err)
		return c.reply(rcEnd, id, []byte("не удалось подключиться"))
	}
	c.smu.Lock()
	if c.streams == nil {
		c.streams = map[uint16]net.Conn{}
	}
	c.streams[id] = conn
	c.smu.Unlock()
	if err := c.reply(rcConnected, id, nil); err != nil {
		return err
	}
	fmt.Println("Поток", id, "открыт")
	go c.pumpStream(id, conn)
	return nil
}

// streamData: байты от клиента в локальный сокет
func (c *circuit) streamData(id uint16, data []byte) error {
	c.smu.Lock()
	conn := c.streams[id]
	c.smu.Unlock()
	if conn == nil {
		return nil // поток уже закрыт, ячейка опоздала
	}
	if _, err := conn.Write(data); err != nil {
		if c.dropStream(id) {
			return c.reply(rcEnd, id, nil)
		}
	}
	return nil
}

// pumpStream: байты из локального сокета клиенту
func (c *circuit) pumpStream(id uint16, conn net.Conn) {
	buf := make([]byte, relCap)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			if c.reply(rcData, id, buf[:n]) != nil {
				c.dropStream(id)
				return
			}
		}
		if err != nil {
			if c.dropStream(id) {
				c.reply(rcEnd, id, nil)
			}
			return
		}
	}
}

// dropStream закрывает поток и говорит, был ли он. END шлём только если был,
// иначе после END от клиента ответили бы ему ещё одним
func (c *circuit) dropStream(id uint16) bool {
	c.smu.Lock()
	conn, ok := c.streams[id]
	delete(c.streams, id)
	c.smu.Unlock()
	if ok {
		fmt.Println("Поток", id, "закрыт")
		conn.Close()
	}
	return ok
}

// closeAll: цепочка умерла, закрываем все потоки
func (c *circuit) closeAll() {
	c.smu.Lock()
	for id, conn := range c.streams {
		conn.Close()
		delete(c.streams, id)
	}
	c.smu.Unlock()
}
