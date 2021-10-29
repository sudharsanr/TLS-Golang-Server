package tls

import (
	"crypto/sha256"
	"fmt"
	"log"
	"net"
	"time"
)

const (
	hostName = "127.0.0.1"
	port     = "8080"
	connType = "tcp"

	caPath     = "files/myCA.crt"
	srvPath    = "files/server.crt"
	srvkeyPath = "files/server.key"

	resp = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\nHello, world!"
)

func CreateServer() {
	l, err := net.Listen(connType, hostName+":"+port)
	if err != nil {
		log.Fatal(err.Error())
	}
	defer l.Close()
	fmt.Println("Listening for connections on port " + port)
	if err != nil {
		log.Fatalln("socket creation failed ", err.Error())
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Fatalln("Error in accepting connection: ", err.Error())
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	state := tlsHandShakeState{
		runningHash: sha256.New(),
	}

	err := recvTLSPart1(conn, &state)
	if err != nil {
		log.Println("Error in connection part1 ", err.Error())
		return
	}

	err = sendTLSPart2(conn, &state)
	if err != nil {
		log.Println("Error in connection part2 ", err.Error())
		return
	}

	err = recvTLSPart3(conn, &state)
	if err != nil {
		log.Println("Error in connection part3 ", err.Error())
		return
	}

	// ccs, finish
	err = sendTLSPart4(conn, &state)
	if err != nil {
		log.Println("Error in connection part4 ", err.Error())
	}
	// transmit Application data from now onwards
	data, err := recvApplicationData(conn, &state)
	if err != nil {
		log.Println("error in receiving app data")
	}
	fmt.Println("data len ", len(data))
	// write app response data

	err = sendApplicationData(conn, []byte(resp), &state)
	if err != nil {
		log.Println("error in sending app data")
	}
	time.Sleep(time.Second)
}
