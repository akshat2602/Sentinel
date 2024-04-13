package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/crypto/pbkdf2"
)

const (
	_reset     = "\033[0m"
	_greenbold = "\033[32;1m"
	_red       = "\033[31m"
)

var logFlags = log.LstdFlags | log.LUTC | log.Lmsgprefix | log.Lshortfile

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
	// 0 for forward proxy, 1 for reverse proxy
	proxyMode int
}

var Pwd []byte

func (rw *ReadFromEncryptDecryptWrite) Read(buf []byte) (int, error) {
	tmpBuf := make([]byte, len(buf))
	n, err := rw.innerRW.Read(tmpBuf)
	copy(buf[:n], tmpBuf[:n])
	return n, err
}

func readBufLength(buf []byte) (uint32, error) {
	// Read the first 4 bytes and convert it to an integer
	if len(buf) < 4 {
		return 0, fmt.Errorf("buffer length is less than 4 bytes")
	}
	var readLen uint32
	tempBufReader := bytes.NewReader(buf)
	err := binary.Read(tempBufReader, binary.BigEndian, &readLen)
	if err != nil {
		return 0, err
	}
	return readLen, nil
}

func prependBufLength(buf []byte) []byte {
	// Prepend the length of the buffer to the buffer
	bufLen := make([]byte, 4)
	binary.BigEndian.PutUint32(bufLen, uint32(len(buf)))
	return append(bufLen, buf...)
}

func (rw *ReadFromEncryptDecryptWrite) ReadFrom(reader io.Reader) (int64, error) {
	var n int
	if rw.proxyMode == 1 {
		buf := make([]byte, 64*1024)
		n, err := reader.Read(buf)
		if err != nil {
			return 0, err
		}
		// Encrypt the data read from the reader and write to the innerRW
		_, err = rw.innerRW.Write(prependBufLength(rw.encryptFunc(buf[:n])))
		if err != nil {
			return 0, err
		}
		clear(buf)
	} else {
		buf := make([]byte, 4)
		_, err := reader.Read(buf)
		if err != nil {
			return 0, err
		}
		readLen, err := readBufLength(buf)
		if err != nil {
			return 0, err
		}
		buf = make([]byte, readLen)
		for i := 0; i < int(readLen); {
			tmpBuf := make([]byte, 1)
			n, err := reader.Read(tmpBuf)
			if err != nil {
				return 0, err
			}
			if n == 1 {
				buf[i] = tmpBuf[0]
				i++
			} else {
				continue
			}
		}
		// n, err := reader.Read(buf)
		// if err != nil {
		// 	return 0, err
		// }
		// Decrypt the data read from the reader and write to the innerRW
		_, err = rw.innerRW.Write(rw.decryptFunc(buf))
		if err != nil {
			return 0, err
		}
		clear(buf)
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
	var n int
	if rw.proxyMode == 1 {
		buf := make([]byte, 4)
		_, err := rw.innerRW.Read(buf)
		if err != nil {
			return 0, err
		}
		readLen, err := readBufLength(buf)
		if err != nil {
			return 0, err
		}
		buf = make([]byte, readLen)
		for i := 0; i < int(readLen); {
			tmpBuf := make([]byte, 1)
			n, err := rw.innerRW.Read(tmpBuf)
			if err != nil {
				return 0, err
			}
			if n == 1 {
				buf[i] = tmpBuf[0]
				i++
			} else {
				continue
			}
		}
		// Decrypt the data read from the innerRW and write to the writer
		_, err = writer.Write(rw.decryptFunc(buf))
		if err != nil {
			return 0, err
		}
		clear(buf)
	} else {
		buf := make([]byte, 64*1024)
		n, err := rw.innerRW.Read(buf)
		if err != nil {
			return 0, err
		}
		// Encrypt the data read from the innerRW and write to the writer
		_, err = writer.Write(prependBufLength(rw.encryptFunc(buf[:n])))
		if err != nil {
			return 0, err
		}
		clear(buf)
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
	// infoLogger.Println("Encryption key:", dk)

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
	// infoLogger.Println("Decryption key:", dk)

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
}

func (p *ProxyConfig) CreateProxyConnection() (net.Conn, error) {
	addr := fmt.Sprintf("%s:%s", p.destination, p.port)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	return conn, nil
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
		}
		// Only handle one connection at a time
		infoLogger.Println("Handling connection from:", client.RemoteAddr())
		go p.handleProxyConnection(client)
	}
}

func (p *ProxyConfig) handleProxyConnection(rw io.ReadWriter) {
	// Establish a connection to the destination server
	fwdConn, err := p.CreateProxyConnection()
	if err != nil {
		errorLogger.Println("Error creating proxy connection:", err.Error())
		return
	}

	derw := &ReadFromEncryptDecryptWrite{
		innerRW:     rw,
		encryptFunc: encryptData,
		decryptFunc: decryptData,
		proxyMode:   p.proxyMode,
	}

	forwardData := func(dest io.Writer, src io.Reader) {
		for {
			_, err := io.Copy(dest, src)
			if err != nil {
				if opErr, ok := err.(*net.OpError); ok && strings.Contains(opErr.Err.Error(), "use of closed network connection") || err == io.EOF {
					infoLogger.Println("Closing connection to ", fwdConn.RemoteAddr())
					fwdConn.Close()
					// Check if rw is a net.Conn and close it
					if conn, ok := rw.(net.Conn); ok {
						infoLogger.Println("Closing connection to", conn.RemoteAddr())
						conn.Close()
					}
					return
				}
				errorLogger.Println("Error forwarding data:", err.Error())
				return
			}
		}
	}
	// If the proxy is a forward proxy, this goroutine will read from the connection(reverse proxy) and write to stdout
	// If the proxy is a reverse proxy, this goroutine will read from the destination server and write to the connection(forward proxy)
	go forwardData(derw, fwdConn)

	// If the proxy is a forward proxy, this goroutine will read from stdin and write to the connection(reverse proxy)
	// If the proxy is a reverse proxy, this goroutine will read from the connection(forward proxy) and write to the destination server
	go forwardData(fwdConn, derw)
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
		proxyMode = 1
		infoLogger.Println("Running in reverse-proxy mode, listening on port:", *listenPort, "for destination:", destination, "port:", port)
	}

	proxyConfig := CreateNewProxyConfig(destination, port, *pwdFile, proxyMode)

	proxyConfig.ReadPasswordFile()

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
