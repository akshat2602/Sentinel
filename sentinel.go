package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

const (
	_reset     = "\033[0m"
	_greenbold = "\033[32;1m"
	_bluebold  = "\033[34;1m"
	_red       = "\033[31m"
)

var logFlags = log.LstdFlags | log.LUTC | log.Lmsgprefix | log.Lshortfile

var debugLogger = log.New(os.Stdout, _bluebold+"[DEBUG] "+_reset, logFlags)
var infoLogger = log.New(os.Stdout, _greenbold+"[INFO] "+_reset, logFlags)
var errorLogger = log.New(os.Stdout, _red+"[ERROR] "+_reset, logFlags)

type ProxyConfig struct {
	destination string
	port        string
	pwdFile     string
	serverConn  *net.Conn
}

func CreateNewProxyConfig(destination string, port string, pwdFile string) *ProxyConfig {
	return &ProxyConfig{
		destination: destination,
		port:        port,
		pwdFile:     pwdFile,
	}
}

func (p *ProxyConfig) CreateProxyConnection() error {
	// TODO: Change this to read the password from the file and establish a secure connection to the destination server
	addr := fmt.Sprintf("%s:%s", p.destination, p.port)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	p.serverConn = &conn
	return nil
}

func (p *ProxyConfig) ListenAndServe(listenPort int) {
	conn, err := net.Listen("tcp", fmt.Sprintf(":%d", listenPort))
	if err != nil {
		errorLogger.Println("Error listening:", err.Error())
		return
	}
	defer conn.Close()

	for {
		client, err := conn.Accept()
		if err != nil {
			errorLogger.Println("Error accepting connection:", err.Error())
			return
		} else {
			debugLogger.Println("Accepted connection from", client.RemoteAddr())
		}
		// Only handle one connection at a time
		p.handleProxyConnection(client)
	}
}

func (p *ProxyConfig) handleProxyConnection(rw io.ReadWriter) {
	conn := *p.serverConn

	// read from client and forward to destination server
	go func() {
		for {
			_, err := io.Copy(rw, conn)
			if err != nil {
				errorLogger.Println("Error forwarding data to destination server:", err.Error())
				return
			}
		}
	}()

	// read from destination server and forward to client
	go func() {
		for {
			_, err := io.Copy(conn, rw)
			if err != nil {
				errorLogger.Println("Error forwarding data to destination server:", err.Error())
				return
			}
			// Check if rw is a bufio.ReadWriter and flush the buffer
			if _, ok := rw.(*bufio.ReadWriter); ok {
				err = rw.(*bufio.ReadWriter).Flush()
				if err != nil {
					errorLogger.Println("Error flushing data to client:", err.Error())
					return
				}
			}

		}
	}()
}

func main() {
	listenPort := flag.Int("l", 0, "Listen port for reverse-proxy mode")
	pwdFile := flag.String("k", "", "Path to the ASCII text passphrase file")
	flag.Parse()

	args := flag.Args()
	if len(args) != 2 {
		errorLogger.Println("Usage: go run jumproxy.go [-l listenport] [-k pwdfile] destination port")
		os.Exit(1)
	}

	destination := args[0]
	port := args[1]

	if *pwdFile == "" {
		errorLogger.Println("No password file provided, exiting..")
		os.Exit(1)
	}

	if *listenPort != 0 {
		infoLogger.Printf("Starting reverse proxy on port %d with destination %s:%s\n", *listenPort, destination, port)
	} else {
		infoLogger.Printf("Starting forward proxy with destination %s:%s\n", destination, port)
	}

	proxyConfig := CreateNewProxyConfig(destination, port, *pwdFile)

	err := proxyConfig.CreateProxyConnection()
	if err != nil {
		errorLogger.Println("Error creating proxy connection:", err.Error())
		os.Exit(1)
	}
	if *listenPort != 0 {
		proxyConfig.ListenAndServe(*listenPort)
	} else {
		scanner := bufio.NewReadWriter(bufio.NewReader(os.Stdin), bufio.NewWriter(os.Stdout))
		proxyConfig.handleProxyConnection(scanner)
	}

	// wait for interrupt signal to exit
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

}
