package blob

import (
	"bytes"
	"encoding/binary"
	"io"
	"sync"
	"unsafe"

	"github.com/illikainen/go-cryptor/src/asymmetric"
	"github.com/illikainen/go-cryptor/src/cryptor"
	"github.com/illikainen/go-cryptor/src/hasher"
	"github.com/illikainen/go-cryptor/src/metadata"
	"github.com/illikainen/go-cryptor/src/symmetric/aesgcm"
	"github.com/illikainen/go-cryptor/src/symmetric/xchacha20poly1305"

	"github.com/illikainen/go-utils/src/iofs"
	"github.com/illikainen/go-utils/src/types"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type Reader struct {
	*Options
	*header

	reader BlobReader
	offset int64
	size   int64

	verified bool
	mutex    sync.Mutex

	chunk []byte
}

func NewReader(r BlobReader, opts *Options) (*Reader, error) {
	if len(opts.Keyring.Public) <= 0 {
		return nil, errors.Errorf("at least one public key must be configured to verify signatures")
	}

	if opts.Encrypted && opts.Keyring.Private == nil {
		return nil, errors.Errorf("a private key must be configured to decrypt")
	}

	stat, err := r.Stat()
	if err != nil {
		return nil, err
	}

	_, err = iofs.Seek(r, 0, io.SeekStart)
	if err != nil {
		return nil, err
	}

	reader := &Reader{
		reader:  r,
		size:    stat.Size(),
		Options: opts,
	}

	reader.header, err = reader.verify()
	if err != nil {
		return nil, err
	}
	reader.offset = reader.headerSize
	reader.verified = true

	return reader, nil
}

func (r *Reader) Metadata() *metadata.Metadata {
	return r.meta
}

func (r *Reader) verify() (*header, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	log.Tracef("verifying %s", r.reader.Name())

	hdr, err := readAndVerifyHeader(r.reader, r.Options)
	if err != nil {
		return nil, err
	}

	hashes, err := hasher.NewWriter()
	if err != nil {
		return nil, err
	}

	err = iofs.Copy(hashes, r.reader)
	if err != nil {
		return nil, err
	}

	err = hashes.Finalize()
	if err != nil {
		return nil, err
	}

	err = hashes.Verify(hdr.meta.Hashes)
	if err != nil {
		return nil, err
	}

	_, err = iofs.Seek(r.reader, hdr.headerSize, io.SeekStart)
	if err != nil {
		return nil, err
	}

	return hdr, nil
}

func (r *Reader) Read(p []byte) (int, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if !r.verified {
		return -1, errors.Errorf("%s has not been verified", r.reader.Name())
	}

	size := len(p)
	var eof error

	for len(r.chunk) < size {
		if r.Encrypted {
			ciphertext := make([]byte, int(r.meta.ChunkSize)+r.xcp.Overhead+r.aes.Overhead)
			n, err := r.reader.Read(ciphertext)
			if n == 0 && err == io.EOF {
				eof = io.EOF
				break
			}
			if err != nil {
				return -1, err
			}

			r.offset += types.Cast[int, int64](n)
			if n != len(ciphertext) && r.offset != r.size {
				return -1, iofs.ErrInvalidSize
			}

			postXcp, err := r.xcp.Decrypt(ciphertext[:n])
			if err != nil {
				return -1, err
			}

			postAes, err := r.aes.Decrypt(postXcp)
			if err != nil {
				return -1, err
			}

			if len(postAes) > int(r.meta.ChunkSize) {
				return -1, iofs.ErrInvalidSize
			}

			r.chunk = append(r.chunk, postAes...)
		} else {
			data := make([]byte, r.meta.ChunkSize)
			n, err := r.reader.Read(data)
			if n == 0 && err == io.EOF {
				eof = io.EOF
				break
			}
			if err != nil {
				return -1, err
			}

			r.offset += types.Cast[int, int64](n)
			if n != len(data) && r.offset != r.size {
				return -1, iofs.ErrInvalidSize
			}

			r.chunk = append(r.chunk, data[:n]...)
		}
	}

	avail := size
	if len(r.chunk) < avail {
		avail = len(r.chunk)
	}
	if copy(p, r.chunk[:avail]) != avail {
		return -1, errors.Errorf("bug")
	}

	r.chunk = r.chunk[avail:]
	return avail, eof
}

func (r *Reader) Seek(offset int64, whence int) (int64, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if !r.verified {
		return -1, errors.Errorf("%s has not been verified", r.reader.Name())
	}

	if offset != 0 || whence != io.SeekStart {
		return -1, cryptor.ErrNotImplemented
	}

	var err error
	r.offset, err = r.reader.Seek(r.headerSize+offset, io.SeekStart)
	if err != nil {
		return -1, err
	}

	if r.offset != r.headerSize+offset {
		return -1, errors.Errorf("bug")
	}

	return r.offset - r.headerSize, nil
}

type header struct {
	meta *metadata.Metadata
	xcp  *xchacha20poly1305.Decrypter
	aes  *aesgcm.Decrypter

	headerBytes []byte
	headerSize  int64
}

func readAndVerifyHeader(reader io.Reader, opts *Options) (*header, error) {
	metadataSize := uint32(0)
	metadataSizeBytes := make([]byte, unsafe.Sizeof(metadataSize)) // #nosec G103
	err := iofs.ReadFull(reader, metadataSizeBytes)
	if err != nil {
		return nil, err
	}

	err = binary.Read(bytes.NewReader(metadataSizeBytes), binary.BigEndian, &metadataSize)
	if err != nil {
		return nil, err
	}
	if metadataSize == 0 {
		return nil, errors.Errorf("invalid metadata size: %d", metadataSize)
	}

	metadataBytes := make([]byte, metadataSize)
	err = iofs.ReadFull(reader, metadataBytes)
	if err != nil {
		return nil, err
	}

	signature := make([]byte, asymmetric.SignatureSize)
	err = iofs.ReadFull(reader, signature)
	if err != nil {
		return nil, err
	}

	for _, pubKey := range opts.Keyring.Public {
		err := pubKey.Verify(metadataBytes, signature)
		if err == nil {
			meta, err := metadata.Read(metadataBytes, opts.Type, opts.Encrypted)
			if err != nil {
				return nil, err
			}

			var aes *aesgcm.Decrypter
			var xcp *xchacha20poly1305.Decrypter
			if opts.Encrypted {
				fpr := opts.Keyring.Private.Fingerprint()
				symKeys, ok := meta.Keys[fpr]
				if !ok {
					return nil, errors.Errorf("missing symmetric keys for %s", fpr)
				}

				xcpKey, err := opts.Keyring.Private.Decrypt(symKeys.XChaCha20Poly1305)
				if err != nil {
					return nil, err
				}

				xcp, err = xchacha20poly1305.NewDecrypter(xcpKey)
				if err != nil {
					return nil, err
				}

				aesKey, err := opts.Keyring.Private.Decrypt(symKeys.AESGCM)
				if err != nil {
					return nil, err
				}

				aes, err = aesgcm.NewDecrypter(aesKey)
				if err != nil {
					return nil, err
				}
			}

			return &header{
				meta:        meta,
				xcp:         xcp,
				aes:         aes,
				headerBytes: append(metadataSizeBytes, append(metadataBytes, signature...)...),
				headerSize: types.Cast[int, int64](len(metadataSizeBytes) +
					len(metadataBytes) +
					len(signature)),
			}, nil
		}
	}

	return nil, errors.Wrapf(cryptor.ErrInvalidSignature, "could not verify signature")
}
