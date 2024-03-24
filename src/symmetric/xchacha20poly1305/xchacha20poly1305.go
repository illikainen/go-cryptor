package xchacha20poly1305

import (
	"crypto/rand"
	"encoding/json"
	"os"

	"github.com/illikainen/go-cryptor/src/cryptor"

	"github.com/illikainen/go-utils/src/errorx"
	"github.com/illikainen/go-utils/src/iofs"
	"github.com/samber/lo"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/chacha20poly1305"
)

type SymmetricKey struct {
	Key       []byte
	ChunkSize int
}

func GenerateKey() (cryptor.SymmetricKey, error) {
	k := SymmetricKey{
		Key:       make([]byte, chacha20poly1305.KeySize),
		ChunkSize: 1024 * 32,
	}
	err := iofs.ReadFull(rand.Reader, k.Key)
	if err != nil {
		return nil, err
	}

	return k, nil
}

func ReadKey(data []byte) (cryptor.SymmetricKey, error) {
	k := SymmetricKey{}
	err := json.Unmarshal(data, &k)
	if err != nil {
		return nil, err
	}

	if len(k.Key) != chacha20poly1305.KeySize {
		return nil, cryptor.ErrInvalidKey
	}

	return k, nil
}

func (k SymmetricKey) Encrypt(in string, out string) (err error) {
	log.Infof("xchacha20poly1305: encrypting...")
	log.Tracef("xchacha20poly1305: in=%s, out=%s", in, out)

	aead, err := chacha20poly1305.NewX(k.Key)
	if err != nil {
		return err
	}

	inf, err := os.Open(in) // #nosec G304
	if err != nil {
		return err
	}
	defer errorx.Defer(inf.Close, &err)

	stat, err := inf.Stat()
	if err != nil {
		return err
	}

	s := stat.Size()
	if s <= 0 || int64(int(s)) != s {
		return iofs.ErrInvalidSize
	}
	size := int(s)

	outf, err := os.Create(out) // #nosec G304
	if err != nil {
		return err
	}
	defer errorx.Defer(outf.Close, &err)

	for size != 0 {
		nonce := make([]byte, aead.NonceSize())
		err = iofs.ReadFull(rand.Reader, nonce)
		if err != nil {
			return err
		}

		chunkSize := lo.Min([]int{k.ChunkSize, size})
		size -= chunkSize

		chunk := make([]byte, chunkSize)
		err = iofs.ReadFull(inf, chunk)
		if err != nil {
			return err
		}

		ciphertext := aead.Seal(nil, nonce, chunk, nil)

		data := append(nonce, ciphertext...)
		n, err := outf.Write(data)
		if err != nil {
			return err
		}
		if len(data) != n {
			return iofs.ErrInvalidSize
		}
	}

	return nil
}

func (k SymmetricKey) Decrypt(in string, out string) (err error) {
	log.Infof("xchacha20poly1305: decrypting...")
	log.Tracef("xchacha20poly1305: in=%s, out=%s", in, out)

	aead, err := chacha20poly1305.NewX(k.Key)
	if err != nil {
		return err
	}

	inf, err := os.Open(in) // #nosec G304
	if err != nil {
		return err
	}
	defer errorx.Defer(inf.Close, &err)

	stat, err := inf.Stat()
	if err != nil {
		return err
	}

	s := stat.Size()
	if s <= 0 || int64(int(s)) != s {
		return iofs.ErrInvalidSize
	}
	size := int(s)

	outf, err := os.Create(out) // #nosec G304
	if err != nil {
		return err
	}
	defer errorx.Defer(outf.Close, &err)

	// The signed metadata with the digests for the entire blob ensures
	// that the chunks haven't been reordered.
	for size != 0 {
		chunkSize := lo.Min([]int{k.ChunkSize + aead.Overhead() + aead.NonceSize(), size})
		size -= chunkSize

		chunk := make([]byte, chunkSize)
		err = iofs.ReadFull(inf, chunk)
		if err != nil {
			return err
		}

		nonce, ciphertext := chunk[:aead.NonceSize()], chunk[aead.NonceSize():]
		plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return err
		}

		n, err := outf.Write(plaintext)
		if err != nil {
			return err
		}
		if n != len(plaintext) {
			return iofs.ErrInvalidSize
		}
	}

	return nil
}

func (k SymmetricKey) Marshal() ([]byte, error) {
	if len(k.Key) != chacha20poly1305.KeySize {
		return nil, cryptor.ErrInvalidKey
	}

	data, err := json.MarshalIndent(k, "", "    ")
	if err != nil {
		return nil, err
	}

	return append(data, '\n'), nil
}
