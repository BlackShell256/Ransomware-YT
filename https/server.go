package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

//private key (.key)
//openssl genrsa -out server.key 2048

//public key based on the private (.key)
//creando un certificado digital con el formato X509
//openssl req -new -x509 -sha256 -key server.key -out server.crt -days 3650

func main() {
	cer, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		panic(err)
	}

	config := &tls.Config{Certificates: []tls.Certificate{cer}}
	ln, err := tls.Listen("tcp", ":4444", config)
	if err != nil {
		panic(err)
	}

	defer ln.Close()

	conn, err := ln.Accept()
	if err != nil {
		panic(err)
	}

	defer conn.Close()
	r := bufio.NewReader(conn)

	k := []byte{}
	for {
		msg, err := r.ReadBytes('\x00')
		if err != nil {
			log.Println(err)
			return
		}

		k = msg
		break
	}
	key := k[:32]
	nonce := k[32:44]
	fmt.Println(key)
	fmt.Println(nonce)

	formato := fmt.Sprintf("key = []byte{%s}\nnonce = []byte{%s}", ConvertToString(key), ConvertToString(nonce))
	err = os.WriteFile("key.txt", []byte(formato), 0644)
	if err != nil {
		panic(err)
	}
}

func ConvertToString(b []byte) string {
	s := make([]string, len(b))
	for i := range b {
		s[i] = strconv.Itoa(int(b[i]))
	}
	return strings.Join(s, ",")
}
