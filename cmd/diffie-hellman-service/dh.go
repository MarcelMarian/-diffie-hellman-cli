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
	P       *big.Int // prime number
	G       *big.Int // generator of p
	KeySize int

	AnswerKey  *big.Int
	PrivateKey *big.Int
}

func NewDh() *Dh {
	return &Dh{}
}

func initDh(dh *Dh, keySize int) error {
	dh.KeySize = keySize
	return nil
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

func CalcEncryptionKey(pubKey []byte) (pub *big.Int, priv *big.Int, sha256 string) {
	bob := NewDh()
	bob.P = new(big.Int)
	bob.G = new(big.Int)
	bob.P.SetBytes([]byte(dhCfgData.DhParams.P))
	bob.G.SetInt64(int64(dhCfgData.DhParams.G))

	bob.PrivateKey, _ = Prime((int)(dhCfgData.DhParams.KeySize))

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
