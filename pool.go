package main

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/flynn/noise"
)

// времена жизни цепочки, у каждой цепочки свой разброс, чтобы все не умирали разом
const (
	dirtyMin = 10 * time.Minute // после первого потока цепочка берёт новые потоки ещё столько
	dirtyMax = 15 * time.Minute
	hardMin  = 30 * time.Minute // потолок жизни от рождения, дальше рубися вместе с потоками
	hardMax  = 60 * time.Minute

	getWait    = 15 * time.Second // сколько новый коннект ждёт готовую цепочку
	sweepEvery = 5 * time.Second
	backoffMax = 30 * time.Second
)

// pooled - цепочка в пуле
type pooled struct {
	id      int
	c       *clientCircuit
	last    int
	hardAt  time.Time
	dirtyAt time.Time // нулевое = ещё ни разу не брали
	users   int       // сколько потоков сейчас идёт по ней
	retired bool      // новые потоки не берёт, доживает пока не закроются старые
	dead    chan struct{}
	once    sync.Once
}

type circuitPool struct {
	cs        noise.CipherSuite
	kp        noise.DHKey
	table     []relayHop
	hopsN     int
	target    string
	targetKey []byte
	size      int

	mu    sync.Mutex
	list  []*pooled
	avail chan struct{} // закрывает, когда в пуле появилась новая цепочка
	nextN int
	wake  chan struct{} // будит maintain, не ждёт тикера
}

func newPool(cs noise.CipherSuite, kp noise.DHKey, table []relayHop, hopsN int, target string, targetKey []byte, size int) *circuitPool {
	return &circuitPool{
		cs: cs, kp: kp, table: table, hopsN: hopsN,
		target: target, targetKey: targetKey, size: size,
		avail: make(chan struct{}),
		wake:  make(chan struct{}, 1),
	}
}

func between(lo, hi time.Duration) time.Duration {
	return lo + time.Duration(rand.Int63n(int64(hi-lo)))
}

func (p *circuitPool) poke() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

// add кладёт готовую цепочку в пул и запускает ей чтение и keepalive
func (p *circuitPool) add(c *clientCircuit) {
	last := len(c.hops) - 1
	p.mu.Lock()
	p.nextN++
	pc := &pooled{
		id:     p.nextN,
		c:      c,
		last:   last,
		hardAt: time.Now().Add(between(hardMin, hardMax)),
		dead:   make(chan struct{}),
	}
	p.list = append(p.list, pc)
	close(p.avail)
	p.avail = make(chan struct{})
	p.mu.Unlock()

	go func() {
		err := c.streamLoop(last)
		p.kill(pc, fmt.Sprint(err))
	}()
	go p.keepalive(pc)
	fmt.Println("Цепочка", pc.id, "в пуле")
}

func (p *circuitPool) keepalive(pc *pooled) {
	t := time.NewTimer(keepGap())
	defer t.Stop()
	for {
		select {
		case <-t.C:
			if err := pc.c.sendTo(pc.last, rcDrop, 0, nil); err != nil {
				p.kill(pc, "keepalive: "+err.Error())
				return
			}
			t.Reset(keepGap())
		case <-pc.dead:
			return
		}
	}
}

// kill вызываем БЕЗ p.mu: внутри он сам берёт мьютекс
func (p *circuitPool) kill(pc *pooled, why string) {
	pc.once.Do(func() {
		close(pc.dead)
		p.mu.Lock()
		for i, x := range p.list {
			if x == pc {
				p.list = append(p.list[:i], p.list[i+1:]...)
				break
			}
		}
		p.mu.Unlock()
		pc.c.closeStreams()
		pc.c.link.conn.Close()
		fmt.Println("Цепочка", pc.id, "закрыта:", why)
		p.poke()
	})
}

// closeStreams закрывает все потоки цепочки, когда она умерла
func (c *clientCircuit) closeStreams() {
	c.smu.Lock()
	ids := make([]uint16, 0, len(c.streams))
	for id := range c.streams {
		ids = append(ids, id)
	}
	c.smu.Unlock()
	for _, id := range ids {
		c.dropStream(id)
	}
}

// get берёт случайную цепочку, которая ещё принимает потоки. Если таких нет,
// ждёт до getWait. users++ делаем тут же под мьютексом, иначе sweep
// мог бы закрыть цепочку между get и началом потока
func (p *circuitPool) get() *pooled {
	deadline := time.Now().Add(getWait)
	for {
		p.mu.Lock()
		var ok []*pooled
		for _, pc := range p.list {
			if !pc.retired {
				ok = append(ok, pc)
			}
		}
		if len(ok) > 0 {
			pc := ok[rand.Intn(len(ok))]
			if pc.dirtyAt.IsZero() {
				pc.dirtyAt = time.Now().Add(between(dirtyMin, dirtyMax))
			}
			pc.users++
			p.mu.Unlock()
			return pc
		}
		ch := p.avail
		p.mu.Unlock()
		p.poke()
		select {
		case <-ch:
		case <-time.After(time.Until(deadline)):
			return nil
		}
	}
}

func (p *circuitPool) release(pc *pooled) {
	p.mu.Lock()
	pc.users--
	p.mu.Unlock()
	p.poke()
}

// need - сколько цепочек не хватает до размера пула (отработавшие не считаем)
func (p *circuitPool) need() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, pc := range p.list {
		if !pc.retired {
			n++
		}
	}
	return p.size - n
}

// sweep: старые цепочки перестают брать потоки, отработавшие и просроченные закрываем
func (p *circuitPool) sweep() {
	type doomed struct {
		pc  *pooled
		why string
	}
	var dead []doomed
	now := time.Now()

	p.mu.Lock()
	for _, pc := range p.list {
		if !pc.retired && !pc.dirtyAt.IsZero() && now.After(pc.dirtyAt) {
			pc.retired = true
			fmt.Println("Цепочка", pc.id, "больше не берёт новые потоки")
		}
		switch {
		case now.After(pc.hardAt):
			dead = append(dead, doomed{pc, "потолок жизни"})
		case pc.retired && pc.users == 0:
			dead = append(dead, doomed{pc, "отработала"})
		}
	}
	p.mu.Unlock()

	for _, d := range dead {
		p.kill(d.pc, d.why)
	}
}

func (p *circuitPool) buildOne() error {
	hops, err := pickHops(p.table, p.hopsN, p.target)
	if err != nil {
		return err
	}
	c, err := buildCircuit(p.cs, p.kp, hops, p.target, p.targetKey)
	if err != nil {
		return err
	}
	p.add(c)
	return nil
}

// maintain держит в пуле size живых цепочек. Строим по одной,
// при ошибке ждём всё дольше (до backoffMax)
func (p *circuitPool) maintain() {
	tick := time.NewTicker(sweepEvery)
	defer tick.Stop()
	fails := 0
	for {
		p.sweep()
		for p.need() > 0 {
			if err := p.buildOne(); err != nil {
				fails++
				wait := time.Duration(fails) * 2 * time.Second
				if wait > backoffMax {
					wait = backoffMax
				}
				fmt.Println("Цепочку построить не вышло:", err, "- повтор через", wait)
				time.Sleep(wait)
				break
			}
			fails = 0
		}
		select {
		case <-tick.C:
		case <-p.wake:
		}
	}
}

// serve слушает локальный порт, один коннект = один поток по случайной цепочке
func (p *circuitPool) serve(local string) error {
	ln, err := net.Listen("tcp", local)
	if err != nil {
		return err
	}
	defer ln.Close()
	fmt.Println("Слушаем локально на", local)

	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go p.handle(conn)
	}
}

func (p *circuitPool) handle(conn net.Conn) {
	pc := p.get()
	if pc == nil {
		fmt.Println("Нет готовой цепочки, соединение отброшено")
		conn.Close()
		return
	}
	// блокируется, пока поток живёт
	pc.c.openStream(pc.last, conn)
	p.release(pc)
}
