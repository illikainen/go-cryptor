package metadata

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/illikainen/go-cryptor/src/hasher"
	"github.com/illikainen/go-cryptor/src/symmetric"

	"github.com/illikainen/go-utils/src/iofs"
	"github.com/illikainen/go-utils/src/stringx"
	"github.com/pkg/errors"
)

type Config struct {
	Type      string
	Encrypted bool
	Keys      map[string]*symmetric.Keys
	ChunkSize uint32
}

type Metadata struct {
	Config
	Version   uint32
	Timestamp int64
	Hashes    *hasher.Writer
}

const Version = 0

func New(config Config) (*Metadata, error) {
	hashes, err := hasher.NewWriter()
	if err != nil {
		return nil, err
	}

	return &Metadata{
		Version:   Version,
		Timestamp: time.Now().Unix(),
		Hashes:    hashes,
		Config:    config,
	}, nil
}

func Read(data []byte, typ string, encrypted bool) (*Metadata, error) {
	if !bytes.Equal(stringx.Sanitize(data), data) {
		return nil, errors.Errorf("metadata contains invalid characters")
	}

	md := &Metadata{}

	err := json.Unmarshal(data, md)
	if err != nil {
		return nil, err
	}

	if md.Type != typ {
		return nil, errors.Errorf("incompatible type (%s vs %s)", md.Type, typ)
	}

	if md.Encrypted != encrypted {
		return nil, errors.Errorf("incompatible encryption config (%v vs %v)", md.Encrypted, encrypted)
	}

	if md.Version != Version {
		return nil, errors.Errorf("incompatible version (%d vs %d)", md.Version, Version)
	}

	return md, err
}

func Size(config Config) (int, error) {
	m, err := New(config)
	if err != nil {
		return -1, err
	}

	data, err := json.Marshal(m)
	if err != nil {
		return -1, err
	}

	size := len(data)
	if size <= 0 {
		return -1, iofs.ErrInvalidSize
	}

	return size, nil
}

func (m *Metadata) MarshalJSON() ([]byte, error) {
	err := m.Hashes.Finalize()
	if err != nil {
		return nil, err
	}

	type alias Metadata
	tmp := alias(*m)

	data, err := json.Marshal(tmp)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(stringx.Sanitize(data), data) {
		return nil, errors.Errorf("metadata contains invalid characters")
	}

	return data, nil
}

func Compare(a *Metadata, b *Metadata) int {
	if b != nil &&
		a.Type == b.Type &&
		a.Version == b.Version &&
		a.Timestamp == b.Timestamp &&
		a.Encrypted == b.Encrypted &&
		*a.Hashes == *b.Hashes {
		return 0
	}
	return 1
}
