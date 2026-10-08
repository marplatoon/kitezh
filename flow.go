package main

import (
	"net"
	"sync"
)

const (
	flowWindow = 1024 // сколько ячеек DATA можно отправить без подтверждения
	flowAck    = 128  // после скольких записанных в сокет ячеек шлём SENDME
)

// flow - один поток с точки зрения любого конца: сокет, очередь записи
// в него и окно для данных, которые мы шлём в другую сторону
type flow struct {
	conn net.Conn
	in   chan []byte   // очередь на запись в conn; nil внутри
	sem  chan struct{} // окно: занятое место = ячейка без подтверждения
	done chan struct{}
	once sync.Once
}

func newFlow(conn net.Conn) *flow {
	return &flow{
		conn: conn,
		in:   make(chan []byte, flowWindow),
		sem:  make(chan struct{}, flowWindow),
		done: make(chan struct{}),
	}
}

// acquire занимает место в окне перед отправкой DATA. Блокируется, пока
// окно полно. false = поток закрыли, пока ждали
func (f *flow) acquire() bool {
	select {
	case f.sem <- struct{}{}:
		return true
	case <-f.done:
		return false
	}
}

// release - пришёл SENDME, освобождаем n мест. Лишние SENDME от чужого
// узла ничего не ломают: канал просто опустеет, и мы остановимся на нуле
func (f *flow) release(n int) {
	for i := 0; i < n; i++ {
		select {
		case <-f.sem:
		default:
			return
		}
	}
}

// push кладёт данные в очередь записи. Копируем, потому что data живёт
// в буфере ячейки. false = очередь полна, а честный отправитель
// столько без SENDME не пошлёт, значит нарушение протокола
func (f *flow) push(data []byte) bool {
	b := make([]byte, len(data))
	copy(b, data)
	select {
	case f.in <- b:
		return true
	default:
		return false
	}
}

// finish: после уже стоящих в очереди данных закрыть поток. Так хвост
// данных перед END не теряется
func (f *flow) finish() bool {
	select {
	case f.in <- nil:
		return true
	default:
		return false
	}
}

// writeLoop - единственный, кто пишет в сокет. Медленный сокет тормозит
// только свой поток, а не цикл цепочки
// ack шлёт SENDME. end вызывается один раз: notify=true, если другой
// стороне надо сообщить END (сокет упал), false - если она сама закрыла
func (f *flow) writeLoop(ack func() error, end func(notify bool)) {
	got := 0
	for {
		select {
		case b := <-f.in:
			if b == nil {
				end(false)
				return
			}
			if _, err := f.conn.Write(b); err != nil {
				end(true)
				return
			}
			got++
			if got%flowAck == 0 && ack() != nil {
				end(false)
				return
			}
		case <-f.done:
			return
		}
	}
}

func (f *flow) close() {
	f.once.Do(func() {
		close(f.done)
		f.conn.Close()
	})
}
