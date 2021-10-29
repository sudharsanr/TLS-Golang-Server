package tls

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"fmt"
	"hash"
	"io/ioutil"
	"log"

	"golang.org/x/crypto/cryptobyte"
)

type tlsHandShakeState struct {
	versionMin, versionMax     []byte
	sessionID                  cryptobyte.String
	extensions                 cryptobyte.String
	clientRandom, serverRandom []byte
	cipherSuites               cryptobyte.String
	runningHash                hash.Hash
	handShakeSum               []byte
	encPreMaster               []byte
	encFinishData              []byte
	decFinishData              [64]byte
	kb                         keyBlock
	premaster, master          []byte
	clientSeq                  [8]byte
	serverSeq                  [8]byte
	appData                    []byte
}

func (state *tlsHandShakeState) upDateHash(data []byte) {
	state.runningHash.Write(data)
	//fmt.Printf("Update hash:%v: % X\n", len(data), data)
}

func (state *tlsHandShakeState) getHash() []byte {
	return state.runningHash.Sum(nil)
}

func (state *tlsHandShakeState) parseClientHello(buf []byte, blen int) error {
	//fmt.Printf("received buf: %d\n", blen)
	cb := cryptobyte.String(buf)
	// assert length inside is less than blen
	var tempByte uint8
	cb.Skip(1) // skip 16 (type)
	cb.ReadBytes(&state.versionMin, 2)
	cb.Skip(2 + 1 + 3)
	cb.ReadBytes(&state.versionMax, 2)
	cb.ReadBytes(&state.clientRandom, 32)
	cb.ReadUint8LengthPrefixed(&state.sessionID)
	cb.ReadUint8LengthPrefixed(&state.cipherSuites)
	cb.ReadUint8(&tempByte)
	cb.Skip(int(tempByte))
	cb.ReadUint16LengthPrefixed(&state.extensions)
	//fmt.Printf("ClientHello: % X\n", buf[5:blen])
	state.upDateHash(buf[5:blen])
	//state.runningHandShakeHash.Write(buf[5:blen])
	return nil
}

func (state *tlsHandShakeState) serverHello() ([]byte, error) {
	state.serverRandom = make([]byte, 32)
	rand.Read(state.serverRandom)
	cb := cryptobyte.Builder{}
	cb.AddBytes([]byte{0x16, 0x03, 0x03})
	cb.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(0x02)
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes([]byte{0x03, 0x03})
			b.AddBytes(state.serverRandom)                         // random
			b.AddBytes([]byte{0x00, 0x00, 0x2f, 0x00, 0x00, 0x00}) // TLS,RSA,AES,128,CBC,SHA
		})
	})
	buf := cb.BytesOrPanic()
	//fmt.Printf("ServerHello: % X\n", buf[5:])
	state.upDateHash(buf[5:])
	//state.runningHandShakeHash.Write(buf[5:])
	return buf, nil
}

func (state *tlsHandShakeState) serverCertificate() ([]byte, error) {
	cb := cryptobyte.Builder{}
	cb.AddBytes([]byte{0x16, 0x03, 0x03})
	cb.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(0x0b)
		// length
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			// clength
			b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
					server, _ := ioutil.ReadFile(srvPath)
					b.AddBytes(server)
				})
				b.AddUint24LengthPrefixed((func(b *cryptobyte.Builder) {
					ca, _ := ioutil.ReadFile(caPath)
					b.AddBytes(ca)
				}))
			})
		})
	})

	buf := cb.BytesOrPanic()
	state.upDateHash(buf[5:])
	return buf, nil
}

func (state *tlsHandShakeState) serverHelloDone() []byte {
	buf := []byte{0x16, 0x03, 0x03, 0x00, 0x04, 0x0e, 0x00, 0x00, 0x00}
	//fmt.Printf("SHdone: % X\n", buf[5:])
	state.upDateHash(buf[5:])
	return buf
}

func (state *tlsHandShakeState) changeCipherSpec() []byte {
	return []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}
}

func (state *tlsHandShakeState) FinishPacket(data []byte) ([]byte, error) {

	/* to be refactored and filled*/

	return nil, nil
}

func (state *tlsHandShakeState) parseClientTLSLastPart(buf []byte, blen int) error {
	cbs := cryptobyte.String(buf)

	cbs.Skip(3)
	var cke, ccs cryptobyte.String
	cbs.ReadUint16LengthPrefixed(&cke)
	//fmt.Printf("Client Key Exchange: % x \n", cke)

	state.upDateHash(cke)
	//state.runningHandShakeHash.Write(cke)
	state.handShakeSum = state.getHash()

	cke.Skip(4)
	cke.ReadUint16LengthPrefixed((*cryptobyte.String)(&state.encPreMaster))
	cbs.Skip(3)
	cbs.ReadUint16LengthPrefixed(&ccs)

	// ccs & finish packet is not included in hash computation
	// only handshake messages are allowed
	cbs.Skip(3)
	cbs.ReadUint16LengthPrefixed((*cryptobyte.String)(&state.encFinishData))

	return nil
}

func (state *tlsHandShakeState) tlsParseClientAppData(buf []byte) ([]byte, error) {

	incSeq(&state.clientSeq)
	cbs := cryptobyte.String(buf)
	cbs.Skip(3)
	cbs.ReadUint16LengthPrefixed((*cryptobyte.String)(&state.appData))

	// decrypt
	decryptAESBlockCipherText(state.appData, state.kb.clientKey, state.kb.clientIv)

	// remove iv, padding and verify mac.
	pad := int(state.appData[len(state.appData)-1])

	// verifyMac, pad
	pad += 21 // mac len + 1 for pad
	pad = len(state.appData) - pad
	cMac := computeMacForAppData(sha1.New, state.kb.clientMac, state.clientSeq[:], state.appData[16:pad])

	if bytes.Compare(cMac, state.appData[pad:pad+20]) != 0 {
		log.Println("Mac verification failure for appdata ")
		return nil, fmt.Errorf("Mac verification failure for appdata ")
	}

	log.Println("Mac verification for appdata done... ")
	return state.appData[16:pad], nil
}

func tlsPadData(buf []byte) []byte {
	if len(buf)%16 != 0 {
		// pad the data
		plen := 16 - (len(buf) % 16)
		for i := 0; i < plen; i++ {
			buf = append(buf, byte(plen-1))
		}
	}

	if len(buf)%16 != 0 {
		log.Fatalf("error in padding data")
	}

	return buf
}

func (state *tlsHandShakeState) tlsGetEncAppData(data []byte) ([]byte, error) {

	incSeq(&state.serverSeq)
	// add iv, data, mac
	cMac := computeMacForAppData(sha1.New, state.kb.serverMac, state.serverSeq[:], data)
	buf := make([]byte, 0, 256)
	buf = append(buf, state.kb.serverIv...)
	buf = append(buf, data...)
	buf = append(buf, cMac...)
	buf = tlsPadData(buf)

	err := encryptAESBlockCipherText(buf, state.kb.serverKey, state.kb.serverIv)
	if err != nil {
		log.Println("Error in encrypting data ", err.Error())
	}
	return buf, nil
}

func (state *tlsHandShakeState) finishPacket() ([]byte, error) {

	var macKey []byte
	macKey = state.kb.serverMac

	finish := make([]byte, 0, 128)
	tempIv := [16]byte{}
	n, err := rand.Read(tempIv[:])
	if err != nil || n != 16 {
		log.Println("error generaing random: %w", err)
		return nil, err
	}

	padding := []byte{0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B}

	// need to update client finish decoded hash
	state.upDateHash(state.decFinishData[16:32])

	state.handShakeSum = state.getHash()
	hsHash := state.handShakeSum

	verifyData := computeVerifyData(state.master, hsHash, []byte(serverFinishLabel))
	mac := computeMacForVerifyData(sha1.New, macKey, state.serverSeq[:], verifyData)
	finish = append(finish, tempIv[:]...)
	finish = append(finish, []byte{0x14, 0x00, 0x00, 0x0C}...)
	finish = append(finish, verifyData...)
	finish = append(finish, mac...)
	finish = append(finish, padding...)
	return finish, nil
}
