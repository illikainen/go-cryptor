package hasher

import (
	"crypto/sha256"
	"encoding/base64"
	"io"
	"os"

	"github.com/illikainen/go-utils/src/errorx"
	"github.com/illikainen/go-utils/src/iofs"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
)

var ErrInvalidHash = errors.New("invalid hash")

type Hasher struct {
	SHA256      string
	KECCAK512   string
	BLAKE2b512  string
	HashedBytes int
}

func New(path string) (h *Hasher, err error) {
	sha256sum := sha256.New()
	keccak512sum := sha3.New512()
	blake2b512sum, err := blake2b.New512(nil)
	if err != nil {
		return nil, errors.Wrap(err, path)
	}

	f, err := os.Open(path) // #nosec G304
	if err != nil {
		return nil, errors.Wrap(err, path)
	}
	defer errorx.Defer(f.Close, &err)

	stat, err := f.Stat()
	if err != nil {
		return nil, errors.Wrap(err, path)
	}
	size := stat.Size()

	actualSize := 0
	for {
		buf := [4096]byte{}
		rn, err := f.Read(buf[:])
		if rn == 0 && err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.Wrap(err, path)
		}
		if rn <= 0 {
			return nil, errors.Errorf("bug")
		}

		wn, err := sha256sum.Write(buf[:rn])
		if err != nil || wn != rn {
			return nil, errors.Errorf("bug")
		}

		wn, err = keccak512sum.Write(buf[:rn])
		if err != nil || wn != rn {
			return nil, errors.Errorf("bug")
		}

		wn, err = blake2b512sum.Write(buf[:rn])
		if err != nil || wn != rn {
			return nil, errors.Errorf("bug")
		}

		actualSize += rn
	}

	if int64(actualSize) != size {
		return nil, errors.Wrap(iofs.ErrInvalidSize, path)
	}

	return &Hasher{
		SHA256:      base64.StdEncoding.EncodeToString(sha256sum.Sum(nil)),
		KECCAK512:   base64.StdEncoding.EncodeToString(keccak512sum.Sum(nil)),
		BLAKE2b512:  base64.StdEncoding.EncodeToString(blake2b512sum.Sum(nil)),
		HashedBytes: actualSize,
	}, nil
}

func (h *Hasher) Verify(path string) (err error) {
	log.Debugf("%s: verifying checksums", path)

	sha256sum := sha256.New()
	keccak512sum := sha3.New512()
	blake2b512sum, err := blake2b.New512(nil)
	if err != nil {
		return err
	}

	f, err := os.Open(path) // #nosec G304
	if err != nil {
		return err
	}
	defer errorx.Defer(f.Close, &err)

	stat, err := f.Stat()
	if err != nil {
		return err
	}
	size := stat.Size()

	actualSize := 0
	for {
		buf := [4096]byte{}
		rn, err := f.Read(buf[:])
		if rn == 0 && err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if rn <= 0 {
			return errors.Errorf("bug")
		}

		wn, err := sha256sum.Write(buf[:rn])
		if err != nil || wn != rn {
			return errors.Errorf("bug")
		}

		wn, err = keccak512sum.Write(buf[:rn])
		if err != nil || wn != rn {
			return errors.Errorf("bug")
		}

		wn, err = blake2b512sum.Write(buf[:rn])
		if err != nil || wn != rn {
			return errors.Errorf("bug")
		}

		actualSize += rn
	}

	if int64(actualSize) != size || actualSize != h.HashedBytes {
		return errors.Wrap(iofs.ErrInvalidSize, path)
	}

	if base64.StdEncoding.EncodeToString(sha256sum.Sum(nil)) != h.SHA256 {
		return errors.Wrapf(ErrInvalidHash, "%s: sha2-256", f.Name())
	}
	log.Infof("sha2-256: verified: %s", h.SHA256)

	if base64.StdEncoding.EncodeToString(keccak512sum.Sum(nil)) != h.KECCAK512 {
		return errors.Wrapf(ErrInvalidHash, "%s: sha3-512", f.Name())
	}
	log.Infof("sha3-512: verified: %s", h.KECCAK512)

	if base64.StdEncoding.EncodeToString(blake2b512sum.Sum(nil)) != h.BLAKE2b512 {
		return errors.Wrapf(ErrInvalidHash, "%s: blake2b-512", f.Name())
	}
	log.Infof("blake2b-512: verified: %s", h.BLAKE2b512)

	return nil
}
