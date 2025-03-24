package xchacha20poly1305

import (
	"bytes"
	"crypto/cipher"
	"math"

	"github.com/illikainen/go-cryptor/src/cryptor"

	"github.com/illikainen/go-utils/src/iofs"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/chacha20poly1305"
)

type Decrypter struct {
	Overhead int
	Key      []byte
	aead     cipher.AEAD
}

func NewDecrypter(key []byte) (*Decrypter, error) {
	if len(key) != chacha20poly1305.KeySize || bytes.Equal(key, make([]byte, chacha20poly1305.KeySize)) {
		return nil, cryptor.ErrInvalidKey
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

	return &Decrypter{
		Overhead: nonceSize + overhead,
		Key:      key,
		aead:     aead,
	}, nil
}

func (d *Decrypter) Decrypt(data []byte) ([]byte, error) {
	log.Tracef("xchacha20poly1305: decrypting %d byte(s)", len(data))

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
