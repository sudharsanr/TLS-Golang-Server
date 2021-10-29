package tls

import (
	"bytes"
	"crypto/sha1"
	"fmt"
	"log"
	"net"

	"golang.org/x/crypto/cryptobyte"
)

func recvTLSPart1(conn net.Conn, state *tlsHandShakeState) error {
	// ClientHello
	buf := make([]byte, 1024)
	blen, err := conn.Read(buf)
	if err != nil {
		fmt.Println("Error in recvtls part1 ", err.Error())
		return err
	}
	err = state.parseClientHello(buf, blen)
	if err != nil {
		log.Println("Error in parsing client Hello ", err.Error())
	}
	return err
}

func sendTLSPart2(conn net.Conn, state *tlsHandShakeState) error {
	//ServerHello, ServerCertificate, SrverHelloDone
	buf1, _ := state.serverHello()
	buf2, _ := state.serverCertificate()
	buf3 := state.serverHelloDone()

	conn.Write(buf1)
	conn.Write(buf2)
	conn.Write(buf3)

	return nil
}

func recvTLSPart3(conn net.Conn, state *tlsHandShakeState) error {
	// clientKeyExchange, CCS, inish
	buf := make([]byte, 2048)
	blen, err := conn.Read(buf)
	if err != nil {
		return err
	}
	err = state.parseClientTLSLastPart(buf, blen)
	return err
}

func sendTLSPart4(conn net.Conn, state *tlsHandShakeState) error {

	var err error
	state.premaster, err = decryptPreMasterSecret(state.encPreMaster, srvkeyPath)
	if err != nil {
		log.Println("Error in decrypting pre master")
		return err
	}
	state.master = computeMasterSecret(state.premaster, state.clientRandom, state.serverRandom)
	state.kb = tlsGenerateKeyBlock(state.clientRandom, state.serverRandom, state.master)
	recvVerifyData := computeVerifyData(state.master, state.handShakeSum, []byte(clientFinishLabel))

	copy(state.decFinishData[:], state.encFinishData[:])

	//decrypt
	err = decryptAESBlockCipherText(state.decFinishData[:], state.kb.clientKey, state.kb.clientIv)
	if err != nil {
		return err
	}

	// verify data
	if bytes.Compare(recvVerifyData, state.decFinishData[20:32]) != 0 {
		log.Println("Verify Data failed")
		return fmt.Errorf("verify failed")
	}
	log.Println("Verify Data is done...")
	sum := computeMacForVerifyData(sha1.New, state.kb.clientMac, state.clientSeq[:], recvVerifyData)
	// verify Mac
	if bytes.Compare(sum, state.decFinishData[32:52]) != 0 {
		log.Println("Mac Verification failed ")
		return fmt.Errorf("mac failed")
	}
	log.Println("Mac verification is done...")

	// send ccs, and our finish packet
	finish, err := state.finishPacket()
	if err != nil {
		log.Println("Error in creating finish packet")
	}

	result := state.changeCipherSpec()
	err = encryptAESBlockCipherText(finish, state.kb.serverKey, state.kb.serverIv)
	if err != nil {
		log.Println("Encryption failed")
		return err
	}

	result = append(result, []byte{0x16, 0x03, 0x03, 0x00, 0x40}...)
	result = append(result, finish...)
	blen, err := conn.Write(result)
	if err != nil || blen != len(result) {
		log.Println("Error in writing server verify data ")
		return err
	}

	return nil
}

func recvApplicationData(conn net.Conn, state *tlsHandShakeState) ([]byte, error) {

	// 2 bytes 64k
	buf := make([]byte, 2048)
	blen, err := conn.Read(buf)
	if err != nil {
		log.Println("Error in reading data ", err.Error())
		return nil, err
	}
	res, err := state.tlsParseClientAppData(buf[:blen])
	return res, err
}

func sendApplicationData(conn net.Conn, resp []byte,
	state *tlsHandShakeState) error {

	encData, err := state.tlsGetEncAppData(resp)
	if err != nil {
		log.Println("Error in creating enc app data", err.Error())
		return err
	}
	cb := cryptobyte.Builder{}
	cb.AddBytes([]byte{0x17, 0x03, 0x03})
	cb.AddUint16LengthPrefixed(func(cb *cryptobyte.Builder) {
		cb.AddBytes(encData)
	})
	n, err := conn.Write(cb.BytesOrPanic())
	if err != nil {
		log.Println("Error in writing app data ", err.Error())
	}
	log.Printf("Response: %v, %v \n", n, len(cb.BytesOrPanic()))
	return nil
}
