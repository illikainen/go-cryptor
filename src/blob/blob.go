package blob

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

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

type Keys struct {
	Public  []cryptor.PublicKey
	Private []cryptor.PrivateKey
}

type Keyring struct {
	NaCl Keys
	RSA  Keys
}

type Keyrings struct {
	Sign    *Keyring
	Encrypt *Keyring
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

	naclSig := make([]byte, naclsig.SignatureSize)
	err = iofs.ReadFull(remotef, naclSig)
	if err != nil {
		return err
	}

	rsaSig := make([]byte, rsa.SignatureSize)
	err = iofs.ReadFull(remotef, rsaSig)
	if err != nil {
		return err
	}

	meta := &metadata.Metadata{}
	err = logging.WithSuppress(func() error {
		meta, err = b.VerifyMetadata(metaData, naclSig, rsaSig)
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

	_, err = localf.Write(naclSig)
	if err != nil {
		return err
	}

	_, err = localf.Write(rsaSig)
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
	if len(b.Keys.Sign.NaCl.Private) == 0 && len(b.Keys.Sign.RSA.Private) == 0 {
		return cryptor.ErrMissingPrivateKey
	}

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

	naclSig := make([]byte, naclsig.SignatureSize)
	if len(b.Keys.Sign.NaCl.Private) > 0 {
		naclSig, err = b.Keys.Sign.NaCl.Private[0].Sign(metaData)
		if err != nil {
			return err
		}

		log.Tracef("metadata: %s: signed json\n%s",
			b.Keys.Sign.NaCl.Private[0].Type(),
			strings.TrimRight(string(metaData), "\x00"),
		)
		log.Infof("metadata: %s: signed with %s",
			b.Keys.Sign.NaCl.Private[0].Type(),
			b.Keys.Sign.NaCl.Private[0].Fingerprint())
	}

	rsaSig := make([]byte, rsa.SignatureSize)
	if len(b.Keys.Sign.RSA.Private) > 0 {
		rsaSig, err = b.Keys.Sign.RSA.Private[0].Sign(metaData)
		if err != nil {
			return err
		}

		log.Tracef("metadata: %s: signed json\n%s",
			b.Keys.Sign.RSA.Private[0].Type(),
			strings.TrimRight(string(metaData), "\x00"),
		)
		log.Infof("metadata: %s: signed with %s",
			b.Keys.Sign.RSA.Private[0].Type(),
			b.Keys.Sign.RSA.Private[0].Fingerprint())
	}

	header := []byte{}
	header = append(header, metaData...)
	header = append(header, naclSig...)
	header = append(header, rsaSig...)

	err = b.Import(tmpBlob, header)
	if err != nil {
		return err
	}

	return nil
}

func (b *Blob) VerifyMetadata(metaData []byte, naclSig []byte, rsaSig []byte) (*metadata.Metadata, error) {
	if len(b.Keys.Sign.NaCl.Public) == 0 && len(b.Keys.Sign.RSA.Public) == 0 {
		return nil, cryptor.ErrMissingPublicKey
	}

	if len(b.Keys.Sign.NaCl.Public) > 0 {
		pubKey, err := b.verifyMetadata(metaData, naclSig, b.Keys.Sign.NaCl.Public)
		if err != nil {
			return nil, err
		}
		log.Infof("metadata: %s: verified: %s", pubKey.Type(), pubKey.Fingerprint())
	}

	if len(b.Keys.Sign.RSA.Public) > 0 {
		pubKey, err := b.verifyMetadata(metaData, rsaSig, b.Keys.Sign.RSA.Public)
		if err != nil {
			return nil, err
		}
		log.Infof("metadata: %s: verified: %s", pubKey.Type(), pubKey.Fingerprint())
	}

	meta, err := metadata.Read(metaData)
	if err != nil {
		return nil, err
	}

	return meta, nil
}

func (b *Blob) verifyMetadata(metaData []byte, signature []byte,
	pubKeys []cryptor.PublicKey) (cryptor.PublicKey, error) {
	for _, pubKey := range pubKeys {
		err := pubKey.Verify(metaData, signature)
		if err == nil {
			return pubKey, nil
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

	naclSig := make([]byte, naclsig.SignatureSize)
	err = iofs.ReadFull(f, naclSig)
	if err != nil {
		return nil, err
	}

	rsaSig := make([]byte, rsa.SignatureSize)
	err = iofs.ReadFull(f, rsaSig)
	if err != nil {
		return nil, err
	}

	meta, err = b.VerifyMetadata(metaData, naclSig, rsaSig)
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
	if len(b.Keys.Encrypt.RSA.Public) <= 0 && len(b.Keys.Encrypt.NaCl.Public) <= 0 {
		return cryptor.ErrMissingPublicKey
	}

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

	if len(b.Keys.Encrypt.RSA.Public) > 0 {
		symKey, err := symmetric.GenerateKey(cryptor.AESGCMSymmetric)
		if err != nil {
			return err
		}

		file := tmpBlob + ".aesgcm"
		err = symKey.Encrypt(tmpBlob, file)
		if err != nil {
			return err
		}
		tmpBlob = file

		symKeyData, err := symKey.Marshal()
		if err != nil {
			return err
		}

		for _, pubKey := range b.Keys.Encrypt.RSA.Public {
			ciphertext, err := pubKey.Encrypt(symKeyData)
			if err != nil {
				return err
			}

			b.symmetricKeys[pubKey.String()] = ciphertext
		}
	}

	if len(b.Keys.Encrypt.NaCl.Public) > 0 {
		symKey, err := symmetric.GenerateKey(cryptor.XCHACHA20POLY1305Symmetric)
		if err != nil {
			return err
		}

		file := tmpBlob + ".xchacha20poly1305"
		err = symKey.Encrypt(tmpBlob, file)
		if err != nil {
			return err
		}
		tmpBlob = file

		symKeyData, err := symKey.Marshal()
		if err != nil {
			return err
		}

		for _, pubKey := range b.Keys.Encrypt.NaCl.Public {
			ciphertext, err := pubKey.Encrypt(symKeyData)
			if err != nil {
				return err
			}

			b.symmetricKeys[pubKey.String()] = ciphertext
		}
	}

	return b.Import(tmpBlob, nil)
}

func (b *Blob) Decrypt(in string, out string, keys map[string]string) (err error) {
	if len(b.Keys.Encrypt.RSA.Private) <= 0 && len(b.Keys.Encrypt.NaCl.Private) <= 0 {
		return cryptor.ErrMissingPrivateKey
	}

	tmpBlob := in
	tmpDir, tmpClean, err := iofs.MkdirTemp()
	if err != nil {
		return err
	}
	defer errorx.Defer(tmpClean, &err)

	if len(b.Keys.Encrypt.NaCl.Private) > 0 {
		for _, privKey := range b.Keys.Encrypt.NaCl.Private {
			ciphertext, ok := keys[privKey.String()]
			if ok {
				symKey, err := privKey.Decrypt(ciphertext)
				if err != nil {
					return err
				}

				sym, err := symmetric.ReadKey(cryptor.XCHACHA20POLY1305Symmetric, symKey)
				if err != nil {
					return err
				}

				file := filepath.Join(tmpDir, "xchacha20poly1305.dec")
				err = sym.Decrypt(tmpBlob, file)
				if err != nil {
					return err
				}
				tmpBlob = file
			}
		}
	}

	if len(b.Keys.Encrypt.RSA.Private) > 0 {
		for _, privKey := range b.Keys.Encrypt.RSA.Private {
			ciphertext, ok := keys[privKey.String()]
			if ok {
				plaintext, err := privKey.Decrypt(ciphertext)
				if err != nil {
					return err
				}

				symKey, err := symmetric.ReadKey(cryptor.AESGCMSymmetric, plaintext)
				if err != nil {
					return err
				}

				file := filepath.Join(tmpDir, "aesgcm.dec")
				err = symKey.Decrypt(tmpBlob, file)
				if err != nil {
					return err
				}
				tmpBlob = file
			}
		}
	}

	return iofs.MoveFile(tmpBlob, out)
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
