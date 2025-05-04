package blob

import (
	"bytes"
	"io"
	"net/url"
	"os"
	"path/filepath"

	"github.com/illikainen/go-cryptor/src/asymmetric"
	"github.com/illikainen/go-cryptor/src/cryptor"
	"github.com/illikainen/go-cryptor/src/hasher"
	"github.com/illikainen/go-cryptor/src/metadata"

	"github.com/illikainen/go-netutils/src/transport"
	"github.com/illikainen/go-utils/src/errorx"
	"github.com/illikainen/go-utils/src/iofs"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type BlobReader interface {
	io.ReadSeeker
	Stat() (os.FileInfo, error)
	Sync() error
	Name() string
}

type BlobWriter interface {
	io.WriteSeeker
}

type BlobReadWriter interface {
	BlobReader
	BlobWriter
	Truncate(int64) error
}

type Keyring struct {
	Public  []cryptor.PublicKey
	Private cryptor.PrivateKey
}

type Options struct {
	Type      string
	Keyring   *Keyring
	Encrypted bool
}

const ChunkSize = 1024 * 32

var ErrSigned = errors.New("the bundle has already been signed")

func ReadKeyring(privkey string, pubkeys []string) (*Keyring, error) {
	var pub []cryptor.PublicKey
	for _, elt := range pubkeys {
		path, err := iofs.Expand(elt)
		if err != nil {
			return nil, err
		}

		pubkey, err := asymmetric.ReadPublicKey(path)
		if err != nil {
			return nil, err
		}

		pub = append(pub, pubkey)
	}

	var priv cryptor.PrivateKey
	if privkey != "" {
		path, err := iofs.Expand(privkey)
		if err != nil {
			return nil, err
		}

		priv, err = asymmetric.ReadPrivateKey(path)
		if err != nil {
			return nil, err
		}
	}

	return &Keyring{Public: pub, Private: priv}, nil
}

func Download(uri *url.URL, rw BlobReadWriter, opts *Options) (r *Reader, err error) {
	log.Tracef("downloading '%s' from '%s'", rw.Name(), uri)

	stat, err := rw.Stat()
	if err != nil {
		return nil, err
	}

	var cacheMeta *metadata.Metadata
	if stat.Size() > 0 {
		cacheHdr, err := readAndVerifyHeader(rw, opts)
		if err != nil {
			return nil, err
		}
		cacheMeta = cacheHdr.Metadata
	}

	xfer, err := transport.New(uri)
	if err != nil {
		return nil, err
	}
	defer errorx.Defer(xfer.Close, &err)

	reader, err := xfer.Open(uri.Path)
	if err != nil {
		return nil, err
	}
	defer errorx.Defer(reader.Close, &err)

	hdr, err := readAndVerifyHeader(reader, opts)
	if err != nil {
		return nil, err
	}

	if metadata.Compare(hdr.Metadata, cacheMeta) <= 0 {
		log.Infof("using cached '%s'", rw.Name())
		return NewReader(rw, opts)
	}

	tmpDir, tmpClean, err := iofs.MkdirTemp()
	if err != nil {
		return nil, err
	}
	defer errorx.Defer(tmpClean, &err)

	tmpFile, err := os.Create(filepath.Join(tmpDir, "blob")) // #nosec G304
	if err != nil {
		return nil, err
	}
	defer errorx.Defer(tmpFile.Close, &err)

	err = iofs.Copy(tmpFile, bytes.NewReader(hdr.headerBytes))
	if err != nil {
		return nil, err
	}

	hashes, err := hasher.NewWriter()
	if err != nil {
		return nil, err
	}

	done := false
	for !done {
		// The documentation for github.com/pkg/sftp states that:
		//
		// > Read follows io.Reader semantics, so when Read encounters
		// > an error or EOF condition after successfully reading N > 0
		// > bytes, it returns the number of bytes read.
		//
		// So we must process the data before checking for EOF.
		buf := [4096]byte{}
		n, err := reader.Read(buf[:])
		if err != nil && err != io.EOF {
			return nil, err
		}
		done = err == io.EOF

		if n < 0 {
			return nil, errors.Errorf("bug")
		} else if n > 0 {
			_, err = hashes.Write(buf[:n])
			if err != nil {
				return nil, err
			}

			err = iofs.Copy(tmpFile, bytes.NewReader(buf[:n]))
			if err != nil {
				return nil, err
			}
		}
	}

	err = hashes.Finalize()
	if err != nil {
		return nil, err
	}

	err = hashes.Verify(hdr.Metadata.Hashes)
	if err != nil {
		return nil, err
	}

	err = tmpFile.Sync()
	if err != nil {
		return nil, err
	}

	_, err = iofs.Seek(tmpFile, 0, io.SeekStart)
	if err != nil {
		return nil, err
	}

	_, err = iofs.Seek(rw, 0, io.SeekStart)
	if err != nil {
		return nil, err
	}

	err = rw.Truncate(0)
	if err != nil {
		return nil, err
	}

	err = iofs.Copy(rw, tmpFile)
	if err != nil {
		return nil, err
	}

	err = rw.Sync()
	if err != nil {
		return nil, err
	}

	return NewReader(rw, opts)
}

func Upload(uri *url.URL, r BlobReader, opts *Options) (err error) {
	log.Infof("uploading '%s' to '%s'", r.Name(), uri)

	_, err = NewReader(r, opts)
	if err != nil {
		return err
	}

	xfer, err := transport.New(uri)
	if err != nil {
		return err
	}
	defer errorx.Defer(xfer.Close, &err)

	err = xfer.Upload(uri.Path, r.Name())
	if err != nil {
		return err
	}

	return nil
}
