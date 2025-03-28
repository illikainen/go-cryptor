package blob

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"sync"
	"unsafe"

	"github.com/illikainen/go-cryptor/src/asymmetric"
	"github.com/illikainen/go-cryptor/src/metadata"
	"github.com/illikainen/go-cryptor/src/symmetric"
	"github.com/illikainen/go-cryptor/src/symmetric/aesgcm"
	"github.com/illikainen/go-cryptor/src/symmetric/xchacha20poly1305"

	"github.com/illikainen/go-utils/src/iofs"
	"github.com/illikainen/go-utils/src/types"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type Writer struct {
	*Options

	writer BlobWriter

	mutex    sync.Mutex
	meta     *metadata.Metadata
	metaSize int

	xcp *xchacha20poly1305.Encrypter
	aes *aesgcm.Encrypter

	chunk  []byte
	signed bool
}

func NewWriter(w BlobWriter, opts *Options) (*Writer, error) {
	_, err := iofs.Seek(w, 0, io.SeekStart)
	if err != nil {
		return nil, err
	}

	if opts.Keyring.Private == nil {
		return nil, errors.Errorf("a private key must be configured to sign")
	}

	var xcp *xchacha20poly1305.Encrypter
	var aes *aesgcm.Encrypter
	symmetricKeys := map[string]*symmetric.Keys{}

	if opts.Encrypted {
		if len(opts.Keyring.Public) <= 0 {
			return nil, errors.Errorf("at least one public key must be configured to encrypt")
		}

		xcp, err = xchacha20poly1305.GenerateKey()
		if err != nil {
			return nil, err
		}

		aes, err = aesgcm.GenerateKey()
		if err != nil {
			return nil, err
		}

		for _, pubKey := range opts.Keyring.Public {
			log.Tracef("encrypting symmetric keys for %s", pubKey)
			symmetricKeys[pubKey.Fingerprint()] = &symmetric.Keys{}

			xcpCiphertext, err := pubKey.Encrypt(xcp.Key)
			if err != nil {
				return nil, err
			}
			symmetricKeys[pubKey.Fingerprint()].XChaCha20Poly1305 = xcpCiphertext

			aesCiphertext, err := pubKey.Encrypt(aes.Key)
			if err != nil {
				return nil, err
			}
			symmetricKeys[pubKey.Fingerprint()].AESGCM = aesCiphertext
		}
	}

	meta, err := metadata.New(metadata.Config{
		Type:      opts.Type,
		Encrypted: opts.Encrypted,
		Keys:      symmetricKeys,
		ChunkSize: ChunkSize,
	})
	if err != nil {
		return nil, err
	}

	metaSize, err := metadata.Size(metadata.Config{
		Type:      opts.Type,
		Encrypted: opts.Encrypted,
		Keys:      symmetricKeys,
		ChunkSize: ChunkSize,
	})
	if err != nil {
		return nil, err
	}

	hdrSize := int64(unsafe.Sizeof(uint32(0))) +
		types.Cast[int, int64](metaSize) +
		asymmetric.SignatureSize // #nosec G103

	_, err = iofs.Seek(w, hdrSize, io.SeekStart)
	if err != nil {
		return nil, err
	}

	return &Writer{
		writer:   w,
		meta:     meta,
		metaSize: metaSize,
		xcp:      xcp,
		aes:      aes,
		signed:   false,
		Options:  opts,
	}, nil
}

func (w *Writer) Write(p []byte) (int, error) {
	if w.signed {
		return -1, ErrSigned
	}

	w.mutex.Lock()
	defer w.mutex.Unlock()

	size := len(p)
	w.chunk = append(w.chunk, p...)
	if len(w.chunk) < ChunkSize {
		return size, nil
	}

	for len(w.chunk) >= ChunkSize {
		chunk := w.chunk[:ChunkSize]
		_, err := w.write(chunk)
		if err != nil {
			return -1, err
		}

		w.chunk = w.chunk[ChunkSize:]
	}

	return size, nil
}

func (w *Writer) write(p []byte) (int, error) {
	if w.Encrypted {
		postAes, err := w.aes.Encrypt(p)
		if err != nil {
			return -1, err
		}

		postXcp, err := w.xcp.Encrypt(postAes)
		if err != nil {
			return -1, err
		}

		n, err := w.writer.Write(postXcp)
		if err != nil {
			return -1, err
		}

		if n != len(postXcp) || n <= w.aes.Overhead-w.xcp.Overhead {
			return -1, iofs.ErrInvalidSize
		}

		_, err = w.meta.Hashes.Write(postXcp)
		if err != nil {
			return -1, err
		}

		return n - w.aes.Overhead - w.xcp.Overhead, nil
	}

	n, err := w.writer.Write(p)
	if err != nil {
		return -1, err
	}

	if n != len(p) {
		return -1, iofs.ErrInvalidSize
	}

	_, err = w.meta.Hashes.Write(p)
	if err != nil {
		return -1, err
	}

	return n, nil
}

func (w *Writer) Sign() error {
	if w.signed {
		return ErrSigned
	}

	w.mutex.Lock()
	defer w.mutex.Unlock()

	if len(w.chunk) > 0 {
		_, err := w.write(w.chunk)
		if err != nil {
			return err
		}

		w.chunk = w.chunk[:0]
	}

	pos, err := w.writer.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}

	startPos, err := w.writer.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}
	if startPos != 0 {
		return errors.Errorf("bug")
	}

	metaBytes, err := json.Marshal(w.meta)
	if err != nil {
		return err
	}

	if len(metaBytes) != w.metaSize {
		return errors.Errorf("invalid metadata size: %d vs %d", len(metaBytes), w.metaSize)
	}

	signature, err := w.Keyring.Private.Sign(metaBytes)
	if err != nil {
		return err
	}

	err = binary.Write(w.writer, binary.BigEndian, types.Cast[int, uint32](len(metaBytes)))
	if err != nil {
		return err
	}

	err = iofs.Copy(w.writer, bytes.NewReader(metaBytes))
	if err != nil {
		return err
	}

	err = iofs.Copy(w.writer, bytes.NewReader(signature))
	if err != nil {
		return err
	}

	resetPos, err := w.writer.Seek(pos, io.SeekStart)
	if err != nil {
		return err
	}
	if resetPos != pos {
		return errors.Errorf("bug")
	}

	w.signed = true
	return nil
}

func (w *Writer) Close() error {
	if !w.signed {
		return w.Sign()
	}
	return nil
}
