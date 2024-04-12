package blob

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/illikainen/go-cryptor/src/asymmetric"
	"github.com/illikainen/go-cryptor/src/asymmetric/naclsig"
	"github.com/illikainen/go-cryptor/src/asymmetric/rsa"
	"github.com/illikainen/go-cryptor/src/cryptor"
	"github.com/illikainen/go-cryptor/src/hasher"
	"github.com/illikainen/go-cryptor/src/metadata"
	"github.com/illikainen/go-cryptor/src/symmetric"

	"github.com/illikainen/go-netutils/src/transport"
	"github.com/illikainen/go-utils/src/errorx"
	"github.com/illikainen/go-utils/src/iofs"
	"github.com/illikainen/go-utils/src/logging"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type Config struct {
	Path      string
	Transport transport.Transport
	Keys      *Keyrings
}

type Blob struct {
	Config
	name          string
	symmetricKeys map[string]string
}

type Keyrings struct {
	Public  []cryptor.PublicKey
	Private cryptor.PrivateKey
}

var ErrInvalidKeyUsage = errors.New("key usage overlap")
var ErrInvalidHeaderSize = errors.New("invalid header size")
var ErrNotVerified = errors.New("the bundle has not been verified")

const headerSize = metadata.MetadataSize + naclsig.SignatureSize + rsa.SignatureSize

func New(config Config) (*Blob, error) {
	_, file := filepath.Split(config.Path)
	b := &Blob{
		Config:        config,
		name:          file,
		symmetricKeys: map[string]string{},
	}

	return b, nil
}

func (b *Blob) HasLocal() (bool, error) {
	return iofs.Exists(b.Path)
}

func (b *Blob) HasRemote(remote string) (bool, error) {
	return b.Transport.Exists(remote)
}

func (b *Blob) Download(remote string) (err error) {
	remotef, err := b.Transport.Open(remote)
	if err != nil {
		return err
	}
	defer errorx.Defer(remotef.Close, &err)

	metaData := make([]byte, metadata.MetadataSize)
	err = iofs.ReadFull(remotef, metaData)
	if err != nil {
		return err
	}

	signature := make([]byte, asymmetric.SignatureSize)
	err = iofs.ReadFull(remotef, signature)
	if err != nil {
		return err
	}

	meta := &metadata.Metadata{}
	err = logging.WithSuppress(func() error {
		meta, err = b.VerifyMetadata(metaData, signature)
		return err
	})
	if err != nil {
		return err
	}

	tmpDir, tmpClean, err := iofs.MkdirTemp()
	if err != nil {
		return err
	}
	defer errorx.Defer(tmpClean, &err)

	cachedMeta := &metadata.Metadata{}
	cachedBlob := ""
	exists, err := b.HasLocal()
	if err != nil {
		return err
	}
	if exists {
		cachedBlob = filepath.Join(tmpDir, fmt.Sprintf("%s.cache", b.name))
		err = logging.WithSuppress(func() error {
			cachedMeta, err = b.Verify(cachedBlob)
			return err
		})
		if err != nil {
			return err
		}
	}

	tmpBlob := filepath.Join(tmpDir, b.name)
	log.Tracef("download: temporary file: %s", tmpBlob)

	localf, err := os.Create(tmpBlob) // #nosec G304
	if err != nil {
		return err
	}
	defer func() {
		if localf != nil {
			err = errorx.Join(err, localf.Close())
		}
	}()

	_, err = localf.Write(metaData)
	if err != nil {
		return err
	}

	_, err = localf.Write(signature)
	if err != nil {
		return err
	}

	if meta.Compare(cachedMeta) == 0 {
		log.Debugf("using cached bundle: %s", cachedBlob)

		err = iofs.Copy(localf, cachedBlob)
		if err != nil {
			return err
		}
	} else {
		log.Debug("downloading...")

		_, err := io.Copy(localf, remotef)
		if err != nil {
			return err
		}
	}

	err = localf.Close()
	if err != nil {
		return err
	}
	localf = nil

	tmpBundle, err := New(Config{Path: tmpBlob, Keys: b.Keys})
	if err != nil {
		return err
	}

	err = logging.WithSuppress(func() error {
		_, err = tmpBundle.Verify("")
		return err
	})
	if err != nil {
		return err
	}

	log.Tracef("download: move %s to %s", tmpBlob, b.Path)
	err = iofs.MoveFile(tmpBlob, b.Path)
	if err != nil {
		return err
	}

	return nil
}

func (b *Blob) Upload(remote string) error {
	return b.Transport.Upload(remote, b.Path)
}

func (b *Blob) Sign() (err error) {
	log.Debugf("signing %s", b.Path)

	tmpDir, tmpClean, err := iofs.MkdirTemp()
	if err != nil {
		return err
	}
	defer errorx.Defer(tmpClean, &err)

	tmpBlob := filepath.Join(tmpDir, b.name)
	err = b.Export(tmpBlob)
	if err != nil {
		return err
	}

	hashes, err := hasher.New(tmpBlob)
	if err != nil {
		return err
	}

	meta, err := metadata.New(hashes, len(b.symmetricKeys) > 0, b.symmetricKeys)
	if err != nil {
		return err
	}

	metaData, err := meta.Marshal()
	if err != nil {
		return err
	}

	signature, err := b.Keys.Private.Sign(metaData)
	if err != nil {
		return err
	}

	log.Tracef("metadata: %s: signed json\n%s",
		b.Keys.Private,
		strings.TrimRight(string(metaData), "\x00"),
	)
	log.Infof("metadata: %s: signed json", b.Keys.Private)

	header := []byte{}
	header = append(header, metaData...)
	header = append(header, signature...)

	err = b.Import(tmpBlob, header)
	if err != nil {
		return err
	}

	return nil
}

func (b *Blob) VerifyMetadata(metaData []byte, signature []byte) (*metadata.Metadata, error) {
	for _, pubKey := range b.Keys.Public {
		err := pubKey.Verify(metaData, signature)
		if err == nil {
			return metadata.Read(metaData)
		}
	}

	return nil, errors.Wrapf(cryptor.ErrInvalidSignature, "could not verify signature")
}

func (b *Blob) Verify(out string) (meta *metadata.Metadata, err error) {
	log.Debugf("verifying %s", b.Path)

	f, err := os.Open(b.Path)
	if err != nil {
		return nil, err
	}
	defer errorx.Defer(f.Close, &err)

	metaData := make([]byte, metadata.MetadataSize)
	err = iofs.ReadFull(f, metaData)
	if err != nil {
		return nil, err
	}

	signature := make([]byte, asymmetric.SignatureSize)
	err = iofs.ReadFull(f, signature)
	if err != nil {
		return nil, err
	}

	meta, err = b.VerifyMetadata(metaData, signature)
	if err != nil {
		return nil, err
	}

	tmpDir, tmpClean, err := iofs.MkdirTemp()
	if err != nil {
		return nil, err
	}
	defer errorx.Defer(tmpClean, &err)

	tmpBlob := filepath.Join(tmpDir, b.name)
	err = b.Export(tmpBlob)
	if err != nil {
		return nil, err
	}

	err = meta.Hashes.Verify(tmpBlob)
	if err != nil {
		return nil, err
	}

	if out != "" {
		err := iofs.MoveFile(tmpBlob, out)
		if err != nil {
			return nil, err
		}
	}

	return meta, nil
}

func (b *Blob) Encrypt() (err error) {
	tmpDir, tmpClean, err := iofs.MkdirTemp()
	if err != nil {
		return err
	}
	defer errorx.Defer(tmpClean, &err)

	tmpBlob := filepath.Join(tmpDir, b.name)
	err = b.Export(tmpBlob)
	if err != nil {
		return err
	}

	aesKey, err := symmetric.GenerateKey(cryptor.AESGCMSymmetric)
	if err != nil {
		return err
	}

	tmpBlobAes := tmpBlob + ".aesgcm"
	err = aesKey.Encrypt(tmpBlob, tmpBlobAes)
	if err != nil {
		return err
	}

	aesKeyData, err := aesKey.Marshal()
	if err != nil {
		return err
	}

	for _, pubKey := range b.Keys.Public {
		ciphertext, err := pubKey.Encrypt(aesKeyData)
		if err != nil {
			return err
		}

		b.symmetricKeys[pubKey.String()+":AESGCM"] = ciphertext
	}

	xcpKey, err := symmetric.GenerateKey(cryptor.XCHACHA20POLY1305Symmetric)
	if err != nil {
		return err
	}

	tmpBlobXCP := tmpBlobAes + ".xchacha20poly1305"
	err = xcpKey.Encrypt(tmpBlobAes, tmpBlobXCP)
	if err != nil {
		return err
	}

	xcpKeyData, err := xcpKey.Marshal()
	if err != nil {
		return err
	}

	for _, pubKey := range b.Keys.Public {
		ciphertext, err := pubKey.Encrypt(xcpKeyData)
		if err != nil {
			return err
		}

		b.symmetricKeys[pubKey.String()+":XChaCha20Poly1305"] = ciphertext
	}

	return b.Import(tmpBlobXCP, nil)
}

func (b *Blob) Decrypt(in string, out string, keys map[string]string) (err error) {
	log.Tracef("%s: decrypt to %s", in, out)

	tmpBlob := in
	tmpDir, tmpClean, err := iofs.MkdirTemp()
	if err != nil {
		return err
	}
	defer errorx.Defer(tmpClean, &err)

	xcpCiphertext, ok := keys[b.Keys.Private.String()+":XChaCha20Poly1305"]
	if !ok {
		return errors.Errorf("missing XChaCha20Poly1305 key")
	}

	xcpPlaintext, err := b.Keys.Private.Decrypt(xcpCiphertext)
	if err != nil {
		return err
	}

	xcpKey, err := symmetric.ReadKey(cryptor.XCHACHA20POLY1305Symmetric, xcpPlaintext)
	if err != nil {
		return err
	}

	partial := filepath.Join(tmpDir, "xchacha20poly1305.dec")
	err = xcpKey.Decrypt(tmpBlob, partial)
	if err != nil {
		return err
	}

	aesCiphertext, ok := keys[b.Keys.Private.String()+":AESGCM"]
	if !ok {
		return errors.Errorf("missing AES-GCM key")
	}

	aesPlaintext, err := b.Keys.Private.Decrypt(aesCiphertext)
	if err != nil {
		return err
	}

	aesKey, err := symmetric.ReadKey(cryptor.AESGCMSymmetric, aesPlaintext)
	if err != nil {
		return err
	}

	plaintext := filepath.Join(tmpDir, "aesgcm.dec")
	err = aesKey.Decrypt(partial, plaintext)
	if err != nil {
		return err
	}

	return iofs.MoveFile(plaintext, out)
}

func (b *Blob) Export(out string) (err error) {
	log.Tracef("%s: blob: exporting %s", b.Path, out)

	inf, err := os.Open(b.Path)
	if err != nil {
		return err
	}
	defer errorx.Defer(inf.Close, &err)

	metaData := make([]byte, metadata.MetadataSize)
	err = iofs.ReadFull(inf, metaData)
	if err != nil {
		return err
	}

	naclSig := make([]byte, naclsig.SignatureSize)
	err = iofs.ReadFull(inf, naclSig)
	if err != nil {
		return err
	}

	rsaSig := make([]byte, rsa.SignatureSize)
	err = iofs.ReadFull(inf, rsaSig)
	if err != nil {
		return err
	}

	outf, err := os.Create(out) // #nosec G304
	if err != nil {
		return err
	}
	defer errorx.Defer(outf.Close, &err)

	_, err = io.Copy(outf, inf)
	if err != nil {
		return err
	}

	return nil
}

func (b *Blob) Import(in string, header []byte) (err error) {
	log.Tracef("%s: blob: importing %s", b.Path, in)

	inf, err := os.Open(in) // #nosec G304
	if err != nil {
		return err
	}
	defer errorx.Defer(inf.Close, &err)

	outf, err := os.Create(b.Path)
	if err != nil {
		return err
	}
	defer errorx.Defer(outf.Close, &err)

	if header == nil {
		header = make([]byte, headerSize)
	}

	_, err = outf.Write(header)
	if err != nil {
		return err
	}

	_, err = io.Copy(outf, inf)
	if err != nil {
		return err
	}

	return nil
}

func (b *Blob) Move(path string) (*Blob, error) {
	log.Infof("%s: moving to %s", b.Path, path)

	newb, err := New(Config{
		Path:      path,
		Transport: b.Transport,
		Keys:      b.Keys,
	})
	if err != nil {
		return nil, err
	}

	err = iofs.MoveFile(b.Path, newb.Path)
	if err != nil {
		return nil, err
	}

	return newb, nil
}
