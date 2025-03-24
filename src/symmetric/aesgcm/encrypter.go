package aesgcm

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"math"

	"github.com/illikainen/go-utils/src/iofs"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type Encrypter struct {
	Overhead int
	Key      []byte
	aead     cipher.AEAD
}

func GenerateKey() (*Encrypter, error) {
	log.Trace("aes256-gcm: generating key")

	key := make([]byte, keySize)
	err := iofs.ReadFull(rand.Reader, key)
	if err != nil {
		return nil, err
	}

	if bytes.Equal(key, make([]byte, keySize)) {
		return nil, errors.Errorf("bug")
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

	return &Encrypter{
		Overhead: nonceSize + overhead,
		Key:      key,
		aead:     aead,
	}, nil
}

func (e *Encrypter) Encrypt(data []byte) ([]byte, error) {
	log.Tracef("aes256-gcm: encrypting %d byte(s)", len(data))

	if len(data) <= 0 {
		return nil, iofs.ErrInvalidSize
	}

	nonce := make([]byte, e.aead.NonceSize())
	err := iofs.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	ciphertext := e.aead.Seal(nil, nonce, data, nil)
	result := append(nonce, ciphertext...)
	if len(result) != len(data)+e.Overhead {
		return nil, iofs.ErrInvalidSize
	}

	return result, nil
}
