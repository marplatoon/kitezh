package main

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/flynn/noise"
)

// команды внутри relay-ячейки (не путать с cmd* линка)
const (
	rcExtend    byte = 1 // продлить цепочку: адрес, ключ хопа, msg1
	rcExtended  byte = 2 // ответ на EXTEND: msg2
	rcData      byte = 3
	rcError     byte = 4 // текст ошибки
	rcDrop      byte = 5
	rcBegin     byte = 6 // открыть поток, адрес не передаём
	rcConnected byte = 7
	rcEnd       byte = 8 // закрыть поток, в данных может быть причина
	rcSendme    byte = 9 // подтверждение: получатель записал flowAck ячеек потока
)

// circuitCfg - что узлу нужно знать про себя
type circuitCfg struct {
	cs      noise.CipherSuite
	kp      noise.DHKey
	allow   map[netip.AddrPort]bool
	onData  func(c *circuit, data []byte) // nil = узел не конечный
	forward string                        // куда вести потоки, "" = потоки выключены
}

type circuit struct {
	cfg     circuitCfg
	in      peer
	hop     *hop
	out     *peer      // следующий узел, nil пока не продлили
	mu      sync.Mutex // в in пишут два цикла
	smu     sync.Mutex // streams
	streams map[uint16]*flow
}

// EXTEND: [len addr 1][addr][ключ хопа 32][msg1 хендшейка хопа]
func buildExtend(addr string, key, msg1 []byte) ([]byte, error) {
	if len(addr) == 0 || len(addr) > 255 || len(key) != keySize {
		return nil, errors.New("плохие параметры EXTEND")
	}
	out := append([]byte{byte(len(addr))}, addr...)
	out = append(out, key...)
	out = append(out, msg1...)
	if len(out) > relCap {
		return nil, errFrameTooLarge
	}
	return out, nil
}

func parseExtend(d []byte) (addr string, key, msg1 []byte, err error) {
	if len(d) < 1 {
		return "", nil, nil, errors.New("пустой EXTEND")
	}
	n := int(d[0])
	if n == 0 || len(d) <= 1+n+keySize {
		return "", nil, nil, errors.New("битый EXTEND")
	}
	return string(d[1 : 1+n]), d[1+n : 1+n+keySize], d[1+n+keySize:], nil
}

// handleCircuit живёт, пока живёт цепочка. Возвращает её, чтобы
// вызывающий мог узнать, какая именно закрылась (nil - не создалась)
func handleCircuit(p peer, cfg circuitCfg) *circuit {
	defer p.conn.Close()
	c := &circuit{cfg: cfg, in: p}
	if err := c.create(); err != nil {
		fmt.Println("Цепочка: не создана:", err)
		return nil
	}
	c.run()
	return c
}

// create ждёт первую ячейку линка и получает ключи хопа
func (c *circuit) create() error {
	c.in.conn.SetDeadline(time.Now().Add(connectTimeout))
	defer c.in.conn.SetDeadline(time.Time{})

	typ, payload, err := recvCmd(c.in)
	if err != nil {
		return err
	}
	switch typ {
	case cmdCreateFast:
		if len(c.in.secret) == 0 {
			return errors.New("у линка нет секрета")
		}
		if c.hop, err = newHop(c.in.secret); err != nil {
			return err
		}
		return sendCmd(c.in, cmdCreated, nil)
	case cmdCreate:
		msg2, h, err := hopAnswer(c.cfg.cs, c.cfg.kp, payload)
		if err != nil {
			return err
		}
		c.hop = h
		return sendCmd(c.in, cmdCreated, msg2)
	}
	return fmt.Errorf("ждали CREATE, пришло %d", typ)
}

// run - цикл "вперёд": снимаем свой слой и решаем, нам это или дальше
func (c *circuit) run() {
	defer c.in.conn.Close()
	defer c.closeAll()
	defer func() {
		if c.out != nil {
			c.out.conn.Close()
		}
	}()
	c.touch()
	for {
		typ, body, err := recvCmd(c.in)
		if err != nil {
			fmt.Println("Цепочка закрыта:", err)
			return
		}
		if typ != cmdRelay || len(body) != cellCap {
			fmt.Println("Цепочка: плохая ячейка")
			return
		}
		c.hop.fwd.XORKeyStream(body, body)
		cmd, stream, data, ok := c.hop.open(body)
		switch {
		case ok:
			if err := c.handle(cmd, stream, data); err != nil {
				fmt.Println("Цепочка:", err)
				return
			}
		case c.out != nil:
			if err := sendCmd(*c.out, cmdRelay, body); err != nil {
				return
			}
		default:
			fmt.Println("Цепочка: ячейка не нам, а дальше некуда")
			return
		}
		c.touch()
	}
}

func (c *circuit) handle(cmd byte, stream uint16, data []byte) error {
	switch cmd {
	case rcExtend:
		return c.extend(data)
	case rcData:
		if stream != 0 {
			return c.streamData(stream, data)
		}
		if c.cfg.onData == nil {
			return errors.New("DATA на промежуточном узле")
		}
		c.cfg.onData(c, data)
		return nil
	case rcBegin:
		return c.beginStream(stream)
	case rcEnd:
		c.endStream(stream)
		return nil
	case rcSendme:
		c.streamSendme(stream)
		return nil
	case rcDrop:
		return nil
	}
	return fmt.Errorf("неизвестная команда %d", cmd)
}

// extend открывает линк до следующего узла, делает CREATE и возвращает
// клиенту msg2. Ошибки клиенту коротко, подробности в лог
func (c *circuit) extend(d []byte) error {
	if c.out != nil {
		return errors.New("цепочка уже продлена")
	}
	addr, key, msg1, err := parseExtend(d)
	if err != nil {
		return err
	}
	fail := func(why string, err error) error {
		fmt.Println("Цепочка: EXTEND к", addr, "не вышел:", why, err)
		return c.reply(rcError, 0, []byte(why))
	}
	if c.cfg.allow != nil && !targetAllowed(c.cfg.allow, addr) {
		return fail("адрес не разрешён", nil)
	}
	fmt.Println("Цепочка: продлеваем к", addr)

	conn, err := dialUTLS(addr)
	if err != nil {
		return fail("не удалось подключиться", err)
	}
	conn.SetDeadline(time.Now().Add(handshakeTimeout))
	recv, send, _, err := handshakeClient(conn, c.cfg.cs, c.cfg.kp, key)
	if err != nil {
		conn.Close()
		return fail("хендшейк линка не прошёл", err)
	}
	outp := peer{conn: conn, send: send, recv: recv}
	if err := sendCmd(outp, cmdCreate, msg1); err != nil {
		conn.Close()
		return fail("CREATE не ушёл", err)
	}
	typ, msg2, err := recvCmd(outp)
	if err != nil || typ != cmdCreated {
		conn.Close()
		return fail("хоп не ответил на CREATE", err)
	}
	conn.SetDeadline(time.Time{})

	c.out = &outp
	go c.pumpBack(outp)
	return c.reply(rcExtended, 0, msg2)
}

// pumpBack - цикл "назад": ячейка от следующего узла, навешиваем слой
func (c *circuit) pumpBack(out peer) {
	defer c.in.conn.Close() // оборвёт и цикл "вперёд"
	for {
		typ, body, err := recvCmd(out)
		if err != nil || typ != cmdRelay || len(body) != cellCap {
			return
		}
		if err := c.sendBack(body); err != nil {
			return
		}
		c.touch()
	}
}

// sendBack: слой и отправка под одним замком, иначе порядок гаммы
// разойдётся с порядком ячеек на линке
func (c *circuit) sendBack(body []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.hop.back.XORKeyStream(body, body)
	return sendCmd(c.in, cmdRelay, body)
}

// reply - ячейка от этого хопа клиенту
func (c *circuit) reply(cmd byte, stream uint16, data []byte) error {
	b, err := c.hop.build(cmd, stream, data)
	if err != nil {
		return err
	}
	return c.sendBack(b)
}

func (c *circuit) touch() {
	d := time.Now().Add(relayIdleTimeout)
	c.in.conn.SetDeadline(d)
	if c.out != nil {
		c.out.conn.SetDeadline(d)
	}
}
