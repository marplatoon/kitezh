package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/flynn/noise"
)

// runChat гоняет двунаправленный зашифрованный чат поверх conn, используя
// уже согласованные после хендшейка ключи. send шифрует то, что мы пишем,
// recv расшифровывает то, что приходит от собеседника. Роль (кто был
// listener, кто dialer) здесь уже не имеет значения

// in - единственный bufio.Reader на stdin для всей программы: если бы
// runClient (ввод IP) и runChat (ввод сообщений) читали stdin каждый
// своим буфером, часть введённого терялась бы в чужом буфере
func runChat(conn net.Conn, send, recv *noise.CipherState, in *bufio.Reader) error {
	// чтение из сети: когда оно кончается (собеседник ушёл, ошибка
	// расшифровки) - результат уходит сюда, и runChat завершается,
	// а не висит дальше на вводе
	netDone := make(chan error, 1)
	go func() { netDone <- readLoop(conn, recv) }()

	// чтение stdin в отдельной горутине: ReadString блокирует, и иначе
	// не смогли бы одновременно ждать и ввод, и конец соединения
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

	for {
		fmt.Print("Введите сообщение: ")
		select {
		case text := <-lines:
			// проврека длины до Encrypt: Encrypt крч увеличивает счётчик
			// nonce внутри CipherState, и зашифрованное, но не
			// отправленное сообщение навсегда рассинхронизировало бы
			// нас с собеседником - все следующие не расшифруются
			if len(text) > maxPlaintext {
				fmt.Printf("Слишком длинное сообщение (%d байт, максимум %d)\n", len(text), maxPlaintext)
				continue
			}
			ciphertext, err := send.Encrypt(nil, nil, []byte(text))
			if err != nil {
				return err
			}
			if err := writeFrame(conn, ciphertext); err != nil {
				return err
			}
		case err := <-netDone:
			return err
		case err := <-inErr:
			// конец stdin (Ctrl+D / Ctrl+Z) - штатный выход, не ошибка по сути (НАВЕРНОЕ)
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

// readLoop читает и расшифровывает входящие фреймы, пока соединение живо
// Нормальное закрытие собеседником (EOF) - не ошибка
func readLoop(conn net.Conn, recv *noise.CipherState) error {
	for {
		ciphertext, err := readFrame(conn)
		if err != nil {
			fmt.Println("\nСоединение закрыто:", err)
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		plaintext, err := recv.Decrypt(nil, nil, ciphertext)
		if err != nil {
			fmt.Println("\nОшибка расшифровки:", err)
			return err
		}
		fmt.Println("\nСобеседник:", string(plaintext))
		fmt.Print("Введите сообщение: ")
	}
}
