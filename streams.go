package main

import (
	"errors"
	"fmt"
	"net"
)

// максимум потоков на одну цепочку, дальше BEGIN отбиваем
const maxStreams = 64

func (c *circuit) getFlow(id uint16) *flow {
	c.smu.Lock()
	defer c.smu.Unlock()
	return c.streams[id]
}

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
	f := newFlow(conn)
	c.smu.Lock()
	if c.streams == nil {
		c.streams = map[uint16]*flow{}
	}
	c.streams[id] = f
	c.smu.Unlock()
	if err := c.reply(rcConnected, id, nil); err != nil {
		return err
	}
	fmt.Println("Поток", id, "открыт")
	go c.pumpStream(id, f)
	go f.writeLoop(
		func() error { return c.reply(rcSendme, id, nil) },
		func(notify bool) {
			if c.dropStream(id) && notify {
				c.reply(rcEnd, id, nil)
			}
		},
	)
	return nil
}

// streamData: байты от клиента уходят в очередь записи, а не прямо в сокет
func (c *circuit) streamData(id uint16, data []byte) error {
	f := c.getFlow(id)
	if f == nil {
		return nil // поток уже закрыт, ячейка опоздала
	}
	if !f.push(data) {
		if c.dropStream(id) {
			return c.reply(rcEnd, id, []byte("окно превышено"))
		}
	}
	return nil
}

// streamSendme: клиент записал наши ячейки, окно освобождается
func (c *circuit) streamSendme(id uint16) {
	if f := c.getFlow(id); f != nil {
		f.release(flowAck)
	}
}

// endStream: клиент закрыл поток. Данные, что он успел прислать до END,
// сначала дописываются в сокет
func (c *circuit) endStream(id uint16) {
	f := c.getFlow(id)
	if f == nil {
		return
	}
	if !f.finish() {
		c.dropStream(id)
	}
}

// pumpStream: байты из локального сокета клиенту, не больше окна
func (c *circuit) pumpStream(id uint16, f *flow) {
	buf := make([]byte, relCap)
	for {
		n, err := f.conn.Read(buf)
		if n > 0 {
			if !f.acquire() {
				return
			}
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
	f, ok := c.streams[id]
	delete(c.streams, id)
	c.smu.Unlock()
	if ok {
		fmt.Println("Поток", id, "закрыт")
		f.close()
	}
	return ok
}

// closeAll: цепочка умерла, закрываем все потоки
func (c *circuit) closeAll() {
	c.smu.Lock()
	for id, f := range c.streams {
		f.close()
		delete(c.streams, id)
	}
	c.smu.Unlock()
}