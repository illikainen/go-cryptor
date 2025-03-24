package xchacha20poly1305

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"math"

	"github.com/illikainen/go-utils/src/iofs"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/chacha20poly1305"
)

type Encrypter struct {
	Overhead int
	Key      []byte
	aead     cipher.AEAD
}

func GenerateKey() (*Encrypter, error) {
	log.Info("xchacha20poly1305: generating key")

	key := make([]byte, chacha20poly1305.KeySize)
	err := iofs.ReadFull(rand.Reader, key)
	if err != nil {
		return nil, err
	}

	if bytes.Equal(key, make([]byte, chacha20poly1305.KeySize)) {
		return nil, errors.Errorf("bug")
	}

	aead, err := chacha20poly1305.NewX(key)
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
	log.Infof("xchacha20poly1305: encrypting %d byte(s)", len(data))

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
