package aesgcm

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"math"

	"github.com/illikainen/go-cryptor/src/cryptor"

	"github.com/illikainen/go-utils/src/iofs"
	log "github.com/sirupsen/logrus"
)

type Decrypter struct {
	Overhead int
	Key      []byte
	aead     cipher.AEAD
}

func NewDecrypter(key []byte) (*Decrypter, error) {
	if len(key) != keySize || bytes.Equal(key, make([]byte, keySize)) {
		return nil, cryptor.ErrInvalidKey
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aead.NonceSize()
	overhead := aead.Overhead()
	if nonceSize < 0 || overhead < 0 || nonceSize > math.MaxInt-overhead {
		return nil, iofs.ErrInvalidSize
	}

	return &Decrypter{
		Overhead: nonceSize + overhead,
		Key:      key,
		aead:     aead,
	}, nil
}

func (d *Decrypter) Decrypt(data []byte) ([]byte, error) {
	log.Tracef("aes256-gcm: decrypting %d byte(s)", len(data))

	if len(data)-d.Overhead <= 0 {
		return nil, iofs.ErrInvalidSize
	}

	nonce := data[:d.aead.NonceSize()]
	ciphertext := data[d.aead.NonceSize():]
	plaintext, err := d.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	if len(plaintext) != len(data)-d.Overhead {
		return nil, iofs.ErrInvalidSize
	}

	return plaintext, nil
}
