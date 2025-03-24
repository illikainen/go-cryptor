package hasher

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"hash"
	"math"

	"github.com/illikainen/go-utils/src/iofs"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
)

type Writer struct {
	Hasher

	sha256      hash.Hash
	keccak512   hash.Hash
	blake2b512  hash.Hash
	hashedBytes int
	finalized   bool
}

func NewWriter() (*Writer, error) {
	sha256hash := sha256.New()
	keccak512hash := sha3.New512()
	blake2b512hash, err := blake2b.New512(nil)
	if err != nil {
		return nil, err
	}

	return &Writer{
		sha256:     sha256hash,
		keccak512:  keccak512hash,
		blake2b512: blake2b512hash,
		finalized:  false,
	}, nil
}

func (w *Writer) Write(p []byte) (int, error) {
	if w.finalized {
		return -1, ErrFinalized
	}

	size := len(p)
	if size <= 0 {
		return -1, iofs.ErrInvalidSize
	}

	sha256n, err := w.sha256.Write(p)
	if err != nil || sha256n != size {
		return -1, iofs.ErrInvalidSize
	}

	keccak512n, err := w.keccak512.Write(p)
	if err != nil || keccak512n != size {
		return -1, iofs.ErrInvalidSize
	}

	blake2b512n, err := w.blake2b512.Write(p)
	if err != nil || blake2b512n != size {
		return -1, iofs.ErrInvalidSize
	}

	w.hashedBytes += size
	return size, nil
}

func (w *Writer) Verify(other *Writer) error {
	if !w.finalized || !other.finalized {
		return ErrNotFinalized
	}

	if w.hashedBytes <= 0 || other.HashedBytes > math.MaxInt || w.hashedBytes != int(other.HashedBytes) {
		return iofs.ErrInvalidSize
	}

	if len(w.SHA256) != 44 || w.SHA256 != other.SHA256 {
		return errors.Wrap(ErrInvalidHash, "sha2-256")
	}
	log.Infof("sha2-256: verified: %s", other.SHA256)

	if len(w.KECCAK512) != 88 || w.KECCAK512 != other.KECCAK512 {
		return errors.Wrap(ErrInvalidHash, "sha3-512")
	}
	log.Infof("sha3-512: verified: %s", other.KECCAK512)

	if len(w.BLAKE2b512) != 88 || w.BLAKE2b512 != other.BLAKE2b512 {
		return errors.Wrap(ErrInvalidHash, "blake2b-512")
	}
	log.Infof("blake2b-512: verified: %s", other.BLAKE2b512)

	return nil
}

func (w *Writer) Finalize() error {
	if !w.finalized {
		w.SHA256 = base64.StdEncoding.EncodeToString(w.sha256.Sum(nil))
		w.KECCAK512 = base64.StdEncoding.EncodeToString(w.keccak512.Sum(nil))
		w.BLAKE2b512 = base64.StdEncoding.EncodeToString(w.blake2b512.Sum(nil))
		w.HashedBytes = FixedUint64(w.hashedBytes)
		w.finalized = true
	}
	return nil
}

func (w *Writer) MarshalJSON() ([]byte, error) {
	if !w.finalized {
		return nil, ErrNotFinalized
	}

	return json.Marshal(w.Hasher)
}

func (w *Writer) UnmarshalJSON(data []byte) error {
	hasher := Hasher{}
	err := json.Unmarshal(data, &hasher)
	if err != nil {
		return err
	}

	w.Hasher = hasher
	w.finalized = true
	return nil
}
