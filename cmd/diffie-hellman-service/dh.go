package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
)

type Dh struct {
	P *big.Int // prime number
	G *big.Int // generator of p

	AnswerKey  *big.Int
	PrivateKey *big.Int
}

// const KEY_SIZE = 512
// const P = "61271898154419322402913024440198123382732149960235057225471551559239770736436621747379793612734389078706272816399549319441301204844108985665478747484068105492425710020816744984827139634377543254232771701666641573615214190348551853310282985759862672269412349682391914493241981043233177573321010505440643093947263406385397608140232899472170776780135562173526944799247913033079971501369669327224164080476260790806304425757096764862596989528589162680331979843703607953840323045069341362184099475644229674957294550371"
// const KEY_SIZE = 256
// const P = "3238753880965754610707105568739490849904386530527757910159357650928335564145344807150033057961040728754572345258544588226658050311871620937068496966107379908371318841510184359376017486618971516252558874080687260635543277811155538694637753722244763834358971"
// const G = 7

func NewDh() *Dh {
	return &Dh{}
}

func (dh *Dh) Public() *big.Int {
	// g^privateKey mod p  ==> return as other side answer key
	return big.NewInt(0).Exp(dh.G, dh.PrivateKey, dh.P)
}

func (dh *Dh) Computes() *big.Int {
	// answerKey^privateKey mod p ==>this is share secret key
	return big.NewInt(0).Exp(dh.AnswerKey, dh.PrivateKey, dh.P)
}

func (dh *Dh) Sha256() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(dh.Computes().String())))
}

func CalcEncryptionKey(pubKey, P []byte) (pub *big.Int, priv *big.Int, sha256 string) {
	bob := NewDh()
	bob.P = new(big.Int)
	bob.G = new(big.Int)
	bob.P.SetBytes([]byte(P))
	bob.G.SetUint64(G)

	bob.PrivateKey, _ = Prime(KEY_SIZE)

	bob.AnswerKey = new(big.Int)
	bob.AnswerKey.SetBytes(pubKey)

	pub = bob.Public()
	priv = bob.Computes()
	return pub, priv, bob.Sha256()
}

func encrypt(stringToEncrypt string, keyString string) (encryptedString string) {

	//Since the key is in string, we need to convert decode it to bytes
	key, _ := hex.DecodeString(keyString)
	plaintext := []byte(stringToEncrypt)

	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	//Create a new GCM - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	//https://golang.org/pkg/crypto/cipher/#NewGCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	//Create a nonce. Nonce should be from GCM
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	//Encrypt the data using aesGCM.Seal
	//Since we don't want to save the nonce somewhere else in this case, we add it as a prefix to the encrypted data. The first nonce argument in Seal is the prefix.
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return fmt.Sprintf("%x", ciphertext)
}

func decrypt(encryptedString string, keyString string) (decryptedString string) {

	key, _ := hex.DecodeString(keyString)
	enc, _ := hex.DecodeString(encryptedString)

	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	//Create a new GCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	//Get the nonce size
	nonceSize := aesGCM.NonceSize()

	//Extract the nonce from the encrypted data
	nonce, ciphertext := enc[:nonceSize], enc[nonceSize:]

	//Decrypt the data
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	return fmt.Sprintf("%s", plaintext)
}
