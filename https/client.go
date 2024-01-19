package main

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"strings"
	"time"
)

func main() {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	for {
		conn, err := tls.Dial("tcp", "192.168.1.10:443", conf)
		if err != nil {
			if strings.Contains(err.Error(), "denegó") {
				time.Sleep(10 * time.Second)
				println(err.Error())
				continue
			}
			panic(err)
		}
		defer conn.Close()

		key := make([]byte, 32)
		nonce := make([]byte, 12)
		_, err = rand.Read(key)
		if err != nil {
			panic(err)
		}
		fmt.Println(key)

		_, err = rand.Read(nonce)
		if err != nil {
			panic(err)
		}
		fmt.Println(nonce)

		key = append(key, nonce...)
		key = append(key, '\x00')

		_, err = conn.Write(key)
		if err != nil {
			panic(err)
		}
		break
	}

}
