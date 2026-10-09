package main

import (
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// TLS 1.3 добавляет к данным заголовок записи 5, тип 1 и тег 16.
// В профиле пишем размер записи на проводе, внутри отнимаем это
const tlsOverhead = 22

const (
	shapeMinWire = 64
	shapeMaxWire = 16384 + tlsOverhead
	maxPending   = 64 * 1024       // дольше этого в очереди не копим, Write блокируется
	closeFlush   = 2 * time.Second // сколько Close ждёт, пока допишется очередь
)

// встроенный профиль. Числа - догадка по кластерам 1405/1413 из одного
// исследования HTTP/2, не снятый дамп. Свой профиль даём через -shape файл
const defaultShapeText = `
# размер записи на проводе, вес
1405 40
1413 30
600 10
300 8
150 7
1000 5
`

// shapeProf - профиль на весь процесс. nil = не шейпим
var shapeProf *shapeProfile

type shapeProfile struct {
	sizes []int // сколько данных кладём в запись (без оверхеда TLS)
	cum   []int // накопленные веса
	total int
}

func (p *shapeProfile) pick() int {
	r := rand.Intn(p.total)
	for i, c := range p.cum {
		if r < c {
			return p.sizes[i]
		}
	}
	return p.sizes[len(p.sizes)-1]
}

// parseShape читает строки "размер вес"
func parseShape(text, name string) (*shapeProfile, error) {
	text = strings.TrimPrefix(text, "\ufeff")
	p := &shapeProfile{}
	for i, line := range strings.Split(text, "\n") {
		n := i + 1
		if j := strings.IndexByte(line, '#'); j >= 0 {
			line = line[:j]
		}
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if len(f) != 2 {
			return nil, fmt.Errorf("%s, строка %d: нужно 'размер вес', а полей %d", name, n, len(f))
		}
		wire, err1 := strconv.Atoi(f[0])
		w, err2 := strconv.Atoi(f[1])
		if err1 != nil || err2 != nil || w < 1 {
			return nil, fmt.Errorf("%s, строка %d: размер и вес - целые числа, вес от 1", name, n)
		}
		if wire < shapeMinWire || wire > shapeMaxWire {
			return nil, fmt.Errorf("%s, строка %d: размер должен быть от %d до %d", name, n, shapeMinWire, shapeMaxWire)
		}
		p.total += w
		p.sizes = append(p.sizes, wire-tlsOverhead)
		p.cum = append(p.cum, p.total)
	}
	if len(p.sizes) == 0 {
		return nil, fmt.Errorf("%s: пустой профиль", name)
	}
	return p, nil
}

// loadShape: "" = встроенный профиль, "off" = без шейпера, иначе путь к файлу.
// юитый файл - ошибка, а не молчаливое "работаем без шейпера"
func loadShape(arg string) (*shapeProfile, error) {
	switch arg {
	case "":
		return parseShape(defaultShapeText, "встроенный профиль")
	case "off":
		return nil, nil
	}
	data, err := os.ReadFile(arg)
	if err != nil {
		return nil, err
	}
	return parseShape(string(data), arg)
}

// shapedConn режет исходящий поток на записи по профилю. Каждый Write
// нижнего соединения = одна TLS-запись. Читает сторона через ReadFull,
type shapedConn struct {
	net.Conn
	prof   *shapeProfile
	mu     sync.Mutex
	cond   *sync.Cond
	buf    []byte
	err    error
	closed bool
	done   chan struct{}
}

func newShaped(c net.Conn, p *shapeProfile) *shapedConn {
	s := &shapedConn{Conn: c, prof: p, done: make(chan struct{})}
	s.cond = sync.NewCond(&s.mu)
	go s.writeLoop()
	return s
}

// Write кладёт данные в очередь и сразу возвращается. Ошибка записи придет со следующим Write
func (s *shapedConn) Write(b []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.buf) >= maxPending && s.err == nil && !s.closed {
		s.cond.Wait()
	}
	if s.err != nil {
		return 0, s.err
	}
	if s.closed {
		return 0, net.ErrClosed
	}
	s.buf = append(s.buf, b...)
	s.cond.Broadcast()
	return len(b), nil
}

func (s *shapedConn) writeLoop() {
	defer close(s.done)
	for {
		s.mu.Lock()
		for len(s.buf) == 0 && !s.closed && s.err == nil {
			s.cond.Wait()
		}
		if s.err != nil || len(s.buf) == 0 {
			s.mu.Unlock()
			return
		}
		n := s.prof.pick()
		if n > len(s.buf) {
			n = len(s.buf)
		}
		// без копии: append пишет только после конца буфера, так что
		// кусок [0:n] никто не затрёт. Главное - не делать s.buf = s.buf[:0]
		chunk := s.buf[:n]
		s.buf = s.buf[n:]
		s.cond.Broadcast() // место в очереди освободилось
		s.mu.Unlock()

		if _, err := s.Conn.Write(chunk); err != nil {
			s.mu.Lock()
			s.err = err
			s.cond.Broadcast()
			s.mu.Unlock()
			return
		}
	}
}

// Close даёт дописаться очереди (не дольше closeFlush), потом закрывает
func (s *shapedConn) Close() error {
	s.mu.Lock()
	s.closed = true
	s.cond.Broadcast()
	s.mu.Unlock()
	select {
	case <-s.done:
	case <-time.After(closeFlush):
	}
	return s.Conn.Close()
}

type shapedListener struct {
	net.Listener
	prof *shapeProfile
}

func (l shapedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return newShaped(c, l.prof), nil
}
