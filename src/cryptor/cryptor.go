package cryptor

import (
	"bytes"
	"encoding/pem"

	"github.com/illikainen/go-utils/src/flag"
	"github.com/pkg/errors"
	"github.com/samber/lo"
	"github.com/spf13/pflag"
)

type PublicKey interface {
	Verify([]byte, []byte) error
	Encrypt([]byte) (string, error)
	Export() ([]byte, error)
	Write(string) error
	Fingerprint() string
	Type() string
	String() string
}

type PrivateKey interface {
	Sign([]byte) ([]byte, error)
	Decrypt(string) ([]byte, error)
	Export() ([]byte, error)
	Write(string) error
	Fingerprint() string
	Type() string
	String() string
}

type SymmetricKey interface {
	Encrypt(string, string) error
	Decrypt(string, string) error
	Marshal() ([]byte, error)
}

const (
	UnknownAsymetric = iota
	NaClAsymmetric
	RSAAsymmetric
)

var AsymmetricMap = map[string]int{
	"nacl": NaClAsymmetric,
	"rsa":  RSAAsymmetric,
}

const (
	UnknownSymmetric = iota
	AESGCMSymmetric
	XCHACHA20POLY1305Symmetric
)

var SymmetricMap = map[string]int{
	"aesgcm":            AESGCMSymmetric,
	"xchacha20poly1305": XCHACHA20POLY1305Symmetric,
}

const (
	UnknownPurpose = iota
	SignPurpose
	EncryptPurpose
)

var PurposeMap = map[string]int{
	"sign":    SignPurpose,
	"encrypt": EncryptPurpose,
}

var ErrInvalidSignature = errors.New("invalid signature")
var ErrInvalidKey = errors.New("invalid key")
var ErrInvalidKeyType = errors.New("invalid key type")
var ErrMultipleKeys = errors.New("multiple keys found in file")
var ErrNotImplemented = errors.New("operation is not implemented for the key type")
var ErrPathExists = errors.New("path already exist")
var ErrInvalidPurpose = errors.New("a key purpose must be specified")
var ErrWrongPurpose = errors.New("key used for the wrong purpose")
var ErrEncrypt = errors.New("encryption failed")
var ErrDecrypt = errors.New("decryption failed")
var ErrMissingPublicKey = errors.New("missing private key")
var ErrMissingPrivateKey = errors.New("missing private key")

func DecodePEM(data []byte) (*pem.Block, error) {
	block, rest := pem.Decode(data)

	if len(rest) != 0 {
		if bytes.Equal(data, rest) {
			return nil, ErrInvalidKey
		}
		return nil, ErrMultipleKeys
	}

	return block, nil
}

type GenerateKeyOptions struct {
	KeyType flag.Enum[int]
	Purpose flag.Enum[int]
	Output  string
}

type GenerateKeyConfig struct {
	Prefix  string
	Sort    bool
	Options *GenerateKeyOptions
}

func GenerateKeyFlags(config GenerateKeyConfig) *pflag.FlagSet {
	flags := pflag.NewFlagSet("genkey", pflag.ContinueOnError)
	flags.SortFlags = config.Sort

	flag.PathVarP(
		flags,
		&config.Options.Output,
		config.Prefix+"output",
		lo.Ternary(config.Prefix == "", "o", ""),
		flag.Path{
			State:    flag.MustNotExist,
			Suffixes: []string{"pub", "priv"},
		},
		"Write the generated keypair to <output>.pub and <output>.priv",
	)

	return flags
}

type SignOptions struct {
	Input  string
	Output string
}

type SignConfig struct {
	Prefix  string
	Sort    bool
	Options *SignOptions
}

func SignFlags(config SignConfig) *pflag.FlagSet {
	flags := pflag.NewFlagSet("sign", pflag.ContinueOnError)
	flags.SortFlags = config.Sort

	flag.PathVarP(
		flags,
		&config.Options.Input,
		config.Prefix+"input",
		lo.Ternary(config.Prefix == "", "i", ""),
		flag.Path{
			State: flag.MustExist,
		},
		"File to sign",
	)

	flag.PathVarP(
		flags,
		&config.Options.Output,
		config.Prefix+"output",
		lo.Ternary(config.Prefix == "", "o", ""),
		flag.Path{
			State:    flag.MustNotExist,
			Suffixes: []string{"pub", "priv"},
		},
		"File to write the signed blob to",
	)

	return flags
}

type VerifyOptions struct {
	Input  string
	Output string
}

type VerifyConfig struct {
	Prefix  string
	Sort    bool
	Options *VerifyOptions
}

func VerifyFlags(config VerifyConfig) *pflag.FlagSet {
	flags := pflag.NewFlagSet("verify", pflag.ContinueOnError)
	flags.SortFlags = config.Sort

	flag.PathVarP(
		flags,
		&config.Options.Input,
		config.Prefix+"input",
		lo.Ternary(config.Prefix == "", "i", ""),
		flag.Path{
			State: flag.MustExist,
		},
		"Input file",
	)

	flag.PathVarP(
		flags,
		&config.Options.Output,
		config.Prefix+"output",
		lo.Ternary(config.Prefix == "", "o", ""),
		flag.Path{
			State: flag.MustNotExist,
		},
		"Output file",
	)

	return flags
}

type EncryptOptions struct {
	Input  string
	Output string
}

type EncryptConfig struct {
	Prefix  string
	Sort    bool
	Options *EncryptOptions
}

func EncryptFlags(config EncryptConfig) *pflag.FlagSet {
	flags := pflag.NewFlagSet("encrypt", pflag.ContinueOnError)
	flags.SortFlags = config.Sort

	flag.PathVarP(
		flags,
		&config.Options.Input,
		config.Prefix+"input",
		lo.Ternary(config.Prefix == "", "i", ""),
		flag.Path{
			State: flag.MustExist,
		},
		"Input file with the plaintext to encrypt",
	)

	flag.PathVarP(
		flags,
		&config.Options.Output,
		config.Prefix+"output",
		lo.Ternary(config.Prefix == "", "o", ""),
		flag.Path{
			State: flag.MustNotExist,
		},
		"Output file for the ciphertext",
	)

	return flags
}

type DecryptOptions struct {
	Input   string
	Output  string
	Extract string
}

type DecryptConfig struct {
	Prefix  string
	Sort    bool
	Options *DecryptOptions
}

func DecryptFlags(config DecryptConfig) *pflag.FlagSet {
	flags := pflag.NewFlagSet("decrypt", pflag.ContinueOnError)
	flags.SortFlags = config.Sort

	flag.PathVarP(
		flags,
		&config.Options.Input,
		config.Prefix+"input",
		lo.Ternary(config.Prefix == "", "i", ""),
		flag.Path{
			State: flag.MustExist,
		},
		"File to verify and decrypt",
	)

	flag.PathVarP(
		flags,
		&config.Options.Output,
		config.Prefix+"output",
		lo.Ternary(config.Prefix == "", "o", ""),
		flag.Path{
			State: flag.MustNotExist,
		},
		"File to write the plaintext to",
	)

	flag.PathVarP(
		flags,
		&config.Options.Extract,
		config.Prefix+"extract",
		lo.Ternary(config.Prefix == "", "e", ""),
		flag.Path{
			State: flag.MustNotExist,
		},
		"Extreact the plaintext to this directory",
	)

	return flags
}
