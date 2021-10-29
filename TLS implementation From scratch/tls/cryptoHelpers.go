package tls

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"hash"
	"io/ioutil"
	"log"

	"golang.org/x/crypto/cryptobyte"
)

const (
	masterSecretLength = 48
	verifyDataLength   = 12

	clientFinishLabel = "client finished"
	serverFinishLabel = "server finished"
	masterSecretLabel = "master secret"
	keyExpansionLabel = "key expansion"
)

//TLS_RSA_AES_128_CBC_SHA
type keyBlock struct {
	clientIv  []byte
	clientMac []byte
	clientKey []byte
	serverIv  []byte
	serverMac []byte
	serverKey []byte
}

func pHash(result, secret, seed []byte, hash func() hash.Hash) {
	/*
			RFC 5246 PRF 12
			P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
		                             HMAC_hash(secret, A(2) + seed) +
		                             HMAC_hash(secret, A(3) + seed) + ...
		      A(0) = seed
		      A(i) = HMAC_hash(secret, A(i-1))

	*/

	h := hmac.New(hash, secret)
	h.Write(seed)
	a := h.Sum(nil) //A(1)

	j := 0
	for j < len(result) {
		h.Reset()
		h.Write(a)
		h.Write(seed)

		b := h.Sum(nil)
		copy(result[j:], b)
		j += len(b)
		//update A
		h.Reset()
		h.Write(a)
		a = h.Sum(nil) // a(i+1)
	}
}

func tls12prf(hashFunc func() hash.Hash, result, secret, label, seed []byte) {

	labelAndSeed := make([]byte, len(label)+len(seed))
	copy(labelAndSeed, label)
	copy(labelAndSeed[len(label):], seed)
	pHash(result, secret, labelAndSeed, hashFunc)
}

func tlsGenerateKeyBlock(clientRandom, serverRandom, master []byte) keyBlock {
	kb := keyBlock{}
	ivsize, keysize, macsize := 16, 16, 20
	kbSize := 2 * (ivsize + macsize + keysize) // iv, key, mac
	keyMaterial := make([]byte, kbSize)
	seed := make([]byte, 0, len(serverRandom)+len(clientRandom))
	seed = append(seed, serverRandom...)
	seed = append(seed, clientRandom...)

	label := []byte(keyExpansionLabel)
	tls12prf(sha256.New, keyMaterial, master, label, seed)

	// copy keys
	kb.clientMac = keyMaterial[:macsize]
	keyMaterial = keyMaterial[macsize:]

	kb.serverMac = keyMaterial[:macsize]
	keyMaterial = keyMaterial[macsize:]

	kb.clientKey = keyMaterial[:keysize]
	keyMaterial = keyMaterial[keysize:]

	kb.serverKey = keyMaterial[:keysize]
	keyMaterial = keyMaterial[keysize:]

	kb.clientIv = keyMaterial[:ivsize]
	keyMaterial = keyMaterial[ivsize:]

	kb.serverIv = keyMaterial[:ivsize]
	return kb
}

func decryptPreMasterSecret(data []byte, path string) ([]byte, error) {

	// read private key from file
	key, err := ioutil.ReadFile(path)
	if err != nil {
		log.Printf("error reading file: %v\n", path)
		return nil, err
	}

	// decode the private key
	priv, err := x509.ParsePKCS1PrivateKey(key)
	if err != nil || priv.Validate() != nil {
		log.Fatalf("bad private key %v", err.Error())
		return nil, err
	}

	premaster, err := priv.Decrypt(
		rand.Reader, data, &rsa.PKCS1v15DecryptOptions{SessionKeyLen: 48})
	if err != nil {
		log.Fatalf("Decryption failed %v ", err.Error())
	}
	return premaster, nil
}

func computeVerifyData(master, msgHash, label []byte) []byte {
	// params ( master, seed, label)
	//  PRF(master_secret, finished_label, Hash(handshake_messages))
	//            [0..verify_data_length-1];
	// label varies for client and server
	verifyData := make([]byte, verifyDataLength)
	tls12prf(sha256.New, verifyData, master, label, msgHash)

	return verifyData
}

func computeMasterSecret(premaster, clientRandom, serverRandom []byte) []byte {
	// master_secret = PRF(pre_master_secret, "master secret",
	//                          ClientHello.random + ServerHello.random)
	seed := make([]byte, 0, len(clientRandom)+len(serverRandom))
	seed = append(seed, clientRandom...)
	seed = append(seed, serverRandom...)
	master := make([]byte, masterSecretLength)
	// label is client finished for client and server finished for server
	label := []byte(masterSecretLabel)

	tls12prf(sha256.New, master, premaster, label, seed)
	return master
}

func decryptAESBlockCipherText(data, key, iv []byte) error {
	aesblock, err := aes.NewCipher(key)
	if err != nil {
		return errors.New("AES Cipher loading failed. Check key")
	}
	mode := cipher.NewCBCDecrypter(aesblock, iv)
	mode.CryptBlocks(data, data)
	return nil
}

func encryptAESBlockCipherText(data, key, iv []byte) error {
	aesblock, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("AES Cipher load failed")
		return errors.New("AES Cipher loading failed. Check key")
	}
	mode := cipher.NewCBCEncrypter(aesblock, iv)
	mode.CryptBlocks(data, data)
	return nil
}

func incSeq(seq *[8]byte) {
	for i := 7; i >= 0; i-- {
		seq[i]++
		if seq[i] != 0 {
			return
		}
	}
	panic("TLS: sequence number wraparound")
}

func computeMacForAppData(hAlg func() hash.Hash, macKey, seqNum, data []byte) []byte {
	h := hmac.New(hAlg, macKey)
	h.Write(seqNum)
	cb := cryptobyte.Builder{}
	cb.AddBytes([]byte{0x17, 0x03, 0x03})
	cb.AddUint16LengthPrefixed(func(cb *cryptobyte.Builder) {
		cb.AddBytes(data)
	})
	buf := cb.BytesOrPanic()
	h.Write(buf)
	return h.Sum(nil)
}

func computeMacForVerifyData(hAlg func() hash.Hash, macKey, seqNum, verifyData []byte) []byte {
	/*MAC(MAC_write_key, seq_num +
		TLSCompressed.type+
		LSCompressed.versio +
	TLSCompressed.length +
		TLSCompressed.fragment;*/

	h := hmac.New(hAlg, macKey)
	h.Write(seqNum)
	h.Write([]byte{0x16, 003, 0x03, 0x00, 0x10})
	h.Write([]byte{0x14, 0x00, 0x00, 0x0C})
	h.Write(verifyData)
	return h.Sum(nil)
}
