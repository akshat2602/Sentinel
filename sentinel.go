package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/crypto/pbkdf2"
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

// this struct encrypts the data read from the innerReader and returns the encrypted data
type ReadFromEncryptDecryptWrite struct {
	innerRW     io.ReadWriter
	encryptFunc func([]byte) []byte
	decryptFunc func([]byte) []byte
	proxyMode   int
}

// ProxyConfig struct to hold the configuration for the proxy in either modes
type ProxyConfig struct {
	destination string
	port        string
	pwdFile     string
	// fwdConn is a pointer to the connection to the destination server(it could either be the reverse proxy or the final destination server based on the mode the proxy is running in)
	fwdConn   *net.Conn
	proxyMode int
}

var Pwd []byte

func (rw *ReadFromEncryptDecryptWrite) Read(buf []byte) (int, error) {
	tmpBuf := make([]byte, len(buf))
	n, err := rw.innerRW.Read(tmpBuf)
	copy(buf[:n], rw.decryptFunc(tmpBuf[:n]))
	return n, err
}

func (rw *ReadFromEncryptDecryptWrite) ReadFrom(reader io.Reader) (int64, error) {
	buf := make([]byte, 64*1024)
	n, err := reader.Read(buf)
	if err != nil {
		return 0, err
	}
	if rw.proxyMode == 1 {
		// Encrypt the data read from the reader and write to the innerRW
		_, err = rw.innerRW.Write(rw.encryptFunc(buf[:n]))
		if err != nil {
			return 0, err
		}
	} else {
		// Decrypt the data read from the reader and write to the innerRW
		_, err = rw.innerRW.Write(rw.decryptFunc(buf[:n]))
		if err != nil {
			return 0, err
		}
	}
	// Flush the buffer if the innerWriter is a bufio.ReadWriter
	if _, ok := rw.innerRW.(*bufio.ReadWriter); ok {
		err := rw.innerRW.(*bufio.ReadWriter).Flush()
		if err != nil {
			return 0, err
		}
	}
	return int64(n), nil
}

func (rw *ReadFromEncryptDecryptWrite) Write(buf []byte) (int, error) {
	n, err := rw.innerRW.Write(buf)
	if err != nil {
		return 0, err
	}
	// Flush the buffer if the innerWriter is a bufio.ReadWriter
	if _, ok := rw.innerRW.(*bufio.ReadWriter); ok {
		err := rw.innerRW.(*bufio.ReadWriter).Flush()
		if err != nil {
			return 0, err
		}
	}
	return n, nil
}

func (rw *ReadFromEncryptDecryptWrite) WriteTo(writer io.Writer) (int64, error) {
	buf := make([]byte, 64*1024)
	n, err := rw.innerRW.Read(buf)
	if err != nil {
		return 0, err
	}
	if rw.proxyMode == 1 {
		// Decrypt the data read from the innerRW and write to the writer
		_, err = writer.Write(rw.decryptFunc(buf[:n]))
		if err != nil {
			return 0, err
		}
	} else {
		// Encrypt the data read from the innerRW and write to the writer
		_, err = writer.Write(rw.encryptFunc(buf[:n]))
		if err != nil {
			return 0, err
		}
	}
	// Flush the buffer if the innerWriter is a bufio.ReadWriter
	if _, ok := rw.innerRW.(*bufio.ReadWriter); ok {
		err := rw.innerRW.(*bufio.ReadWriter).Flush()
		if err != nil {
			return 0, err
		}
	}
	return int64(n), nil
}

func encryptData(data []byte) []byte {
	dk := pbkdf2.Key(Pwd, []byte("fixedyourmom"), 4096, 32, sha1.New)
	// debugLogger.Println("Encryption key:", dk)

	block, err := aes.NewCipher(dk)
	if err != nil {
		errorLogger.Println("Error creating new cipher:", err.Error())
		panic(err.Error())
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		errorLogger.Println("Error generating nonce:", err.Error())
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		errorLogger.Println("Error creating new GCM:", err.Error())
		panic(err.Error())
	}

	data = aesgcm.Seal(nil, nonce, data, nil)
	data = append(nonce, data...)

	return data
}

func decryptData(data []byte) []byte {
	dk := pbkdf2.Key(Pwd, []byte("fixedyourmom"), 4096, 32, sha1.New)
	// debugLogger.Println("Decryption key:", dk)

	block, err := aes.NewCipher(dk)
	if err != nil {
		errorLogger.Println("Error creating new cipher:", err.Error())
		panic(err.Error())
	}

	nonce := data[:12]
	data = data[12:]

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		errorLogger.Println("Error creating new GCM:", err.Error())
		panic(err.Error())
	}

	data, err = aesgcm.Open(nil, nonce, data, nil)
	if err != nil {
		errorLogger.Println("Error decrypting data:", err.Error())
		panic(err.Error())
	}

	return data
}

func CreateNewProxyConfig(destination string, port string, pwdFile string, proxyMode int) *ProxyConfig {
	return &ProxyConfig{
		destination: destination,
		port:        port,
		pwdFile:     pwdFile,
		proxyMode:   proxyMode,
	}
}

func (p *ProxyConfig) ReadPasswordFile() {
	file, err := os.Open(p.pwdFile)
	if err != nil {
		errorLogger.Println("Error opening password file:", err.Error())
		os.Exit(1)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		Pwd = scanner.Bytes()
	}
	if err := scanner.Err(); err != nil {
		errorLogger.Println("Error reading password file:", err.Error())
		os.Exit(1)
	}
	// infoLogger.Println("Password read from file:", string(Pwd))
}

func (p *ProxyConfig) CreateProxyConnection() error {
	addr := fmt.Sprintf("%s:%s", p.destination, p.port)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	p.fwdConn = &conn
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
			// debugLogger.Println("Accepted connection from", client.RemoteAddr())
		}
		// Only handle one connection at a time
		p.handleProxyConnection(client)
	}
}

func (p *ProxyConfig) handleProxyConnection(rw io.ReadWriter) {
	fwdConn := *p.fwdConn

	// If the proxy is a forward proxy, this goroutine will read from the connection(reverse proxy) and write to stdout
	// If the proxy is a reverse proxy, this goroutine will read from the destination server and write to the connection(forward proxy)
	go func() {
		derw := &ReadFromEncryptDecryptWrite{
			innerRW:     rw,
			encryptFunc: encryptData,
			decryptFunc: decryptData,
			proxyMode:   p.proxyMode,
		}
		for {
			_, err := io.Copy(derw, fwdConn)
			if err != nil {
				errorLogger.Println("Error forwarding data:", err.Error())
				return
			}
		}
	}()

	// If the proxy is a forward proxy, this goroutine will read from stdin and write to the connection(reverse proxy)
	// If the proxy is a reverse proxy, this goroutine will read from the connection(forward proxy) and write to the destination server
	go func() {
		derw := &ReadFromEncryptDecryptWrite{
			innerRW:     rw,
			encryptFunc: encryptData,
			decryptFunc: decryptData,
			proxyMode:   p.proxyMode,
		}
		for {
			_, err := io.Copy(fwdConn, derw)
			if err != nil {
				errorLogger.Println("Error forwarding data:", err.Error())
				return
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

	proxyMode := 0
	if *listenPort != 0 {
		// infoLogger.Printf("Starting reverse proxy on port %d with destination %s:%s\n", *listenPort, destination, port)
		proxyMode = 1
	} else {
		// infoLogger.Printf("Starting forward proxy with destination %s:%s\n", destination, port)
	}

	proxyConfig := CreateNewProxyConfig(destination, port, *pwdFile, proxyMode)

	proxyConfig.ReadPasswordFile()

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
