package hasher

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"unsafe"

	"github.com/pkg/errors"
)

var ErrInvalidHash = errors.New("invalid hash")
var ErrFinalized = errors.New("hasher has already been finalized")
var ErrNotFinalized = errors.New("hasher has not been finalized")

type Hasher struct {
	SHA256      string
	KECCAK512   string
	BLAKE2b512  string
	HashedBytes FixedUint64
}

type FixedUint64 uint64

func (n FixedUint64) MarshalJSON() ([]byte, error) {
	width := len(fmt.Sprintf("%d", uint64(math.MaxUint64)))
	return json.Marshal(fmt.Sprintf("%0*d", width, n))
}

func (n *FixedUint64) UnmarshalJSON(data []byte) error {
	var s string
	err := json.Unmarshal(data, &s)
	if err != nil {
		return err
	}

	conv, err := strconv.ParseInt(s, 10, int(unsafe.Sizeof(*n))*8) // #nosec G103
	if err != nil {
		return err
	}

	*n = FixedUint64(conv)
	return nil
}
