package cryptor_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/illikainen/go-cryptor/src/blob"
	"github.com/illikainen/go-cryptor/src/hasher"

	"github.com/illikainen/go-utils/src/iofs"
	"github.com/pkg/errors"
)

type output struct {
	Path   string
	Data   string
	SHA256 string
}

func TestFingerprint(t *testing.T) {
	keyring, err := blob.ReadKeyring(privKey(t), pubKeys(t))
	if err != nil {
		t.Fatalf("%v", err)
	}

	fpr := "fE6iwxROYXn2iBsTwOhRfFEVw2TIdsHqwDl1Uqx2aRiNL0XsOVVFHwMv9CeUsstR4k1L+TWDnTTO5wIjoQTt6Q=="
	if keyring.Private.Fingerprint() != fpr {
		t.Fatalf("bad fingerprint: %s != %s", keyring.Private.Fingerprint(), fpr)
	}

	for _, pubKey := range keyring.Public {
		if pubKey.Fingerprint() != fpr {
			t.Fatalf("bad fingerprint: %s != %s", pubKey.Fingerprint(), fpr)
		}
	}
}

func TestDecrypt(t *testing.T) {
	tests := []string{
		"",
		"line1",
		"line1\nline2\nline3",
		"foo" + strings.Repeat("ABC", 1024),
		"foo" + strings.Repeat("ABC", 1024*64),
	}

	for _, data := range tests {
		path, sha256sum := seal([]byte(data), true, t)

		out := unsealpy(path, true, t)
		if len(out) != 1 {
			t.Fatalf("invalid out length: %d", len(out))
		}

		if out[0].SHA256 != sha256sum {
			t.Fatalf("invalid sha256: %s != %s", out[0].SHA256, sha256sum)
		}

		if out[0].Data != base64.StdEncoding.EncodeToString([]byte(data)) {
			t.Fatalf("invalid data: %s != %s", out[0].Data, data)
		}

		if data != "" && bytes.Contains(readFile(path, t), []byte(data)) {
			t.Fatal("invalid data")
		}
	}
}

func TestDecryptAdditionalData(t *testing.T) {
	tests := []string{
		"line1",
		"line1\nline2\nline3",
		"foo" + strings.Repeat("ABC", 1024),
		"foo" + strings.Repeat("ABC", 1024*64),
	}

	for _, data := range tests {
		path, sha256sum := seal([]byte(data), true, t)

		goodData, goodSha256 := unseal(path, true, t)
		if goodSha256 != sha256sum {
			t.Fatalf("invalid sha256: %s != %s", goodSha256, sha256sum)
		}

		if !bytes.Equal(goodData, []byte(data)) {
			t.Fatalf("invalid data: %s != %s", goodData, data)
		}

		outf, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600) // #nosec G304
		if err != nil {
			t.Fatalf("%v", err)
		}

		_, err = outf.Write([]byte("\x00"))
		if err != nil {
			t.Fatalf("%v", err)
		}

		err = outf.Close()
		if err != nil {
			t.Fatalf("%v", err)
		}

		inf, err := os.Open(path) // #nosec G304
		if err != nil {
			t.Fatalf("%v", err)
		}

		keyring, err := blob.ReadKeyring(privKey(t), pubKeys(t))
		if err != nil {
			t.Fatalf("%v", err)
		}

		_, err = blob.NewReader(inf, &blob.Options{
			Type:      "cryptor-test",
			Keyring:   keyring,
			Encrypted: true,
		})
		if !errors.Is(err, iofs.ErrInvalidSize) {
			t.Fatalf("expected invalid size error")

		}

		err = inf.Close()
		if err != nil {
			t.Fatalf("%v", err)
		}
	}
}

func TestDecryptOverwrittenData(t *testing.T) {
	tests := []string{
		"line1",
		"line1\nline2\nline3",
		"foo" + strings.Repeat("ABC", 1024),
		"foo" + strings.Repeat("ABC", 1024*64),
	}

	for _, data := range tests {
		path, sha256sum := seal([]byte(data), true, t)

		goodData, goodSha256 := unseal(path, true, t)
		if goodSha256 != sha256sum {
			t.Fatalf("invalid sha256: %s != %s", goodSha256, sha256sum)
		}

		if !bytes.Equal(goodData, []byte(data)) {
			t.Fatalf("invalid data: %s != %s", goodData, data)
		}

		outf, err := os.OpenFile(path, os.O_RDWR, 0600) // #nosec G304
		if err != nil {
			t.Fatalf("%v", err)
		}

		_, err = outf.Seek(-1, io.SeekEnd)
		if err != nil {
			t.Fatalf("%v", err)
		}

		_, err = outf.Write([]byte("\x00"))
		if err != nil {
			t.Fatalf("%v", err)
		}

		err = outf.Close()
		if err != nil {
			t.Fatalf("%v", err)
		}

		inf, err := os.Open(path) // #nosec G304
		if err != nil {
			t.Fatalf("%v", err)
		}

		keyring, err := blob.ReadKeyring(privKey(t), pubKeys(t))
		if err != nil {
			t.Fatalf("%v", err)
		}

		_, err = blob.NewReader(inf, &blob.Options{
			Type:      "cryptor-test",
			Keyring:   keyring,
			Encrypted: true,
		})

		if !errors.Is(err, hasher.ErrInvalidHash) {
			t.Fatalf("expected invalid hash error")

		}

		err = inf.Close()
		if err != nil {
			t.Fatalf("%v", err)
		}
	}
}

func TestVerify(t *testing.T) {
	tests := []string{
		"",
		"line1",
		"line1\nline2\nline3",
		"foo" + strings.Repeat("ABC", 1024),
		"foo" + strings.Repeat("ABC", 1024*64),
	}

	for _, data := range tests {
		path, sha256sum := seal([]byte(data), false, t)

		out := unsealpy(path, false, t)
		if len(out) != 1 {
			t.Fatalf("invalid out length: %d", len(out))
		}

		if out[0].SHA256 != sha256sum {
			t.Fatalf("invalid sha256: %s != %s", out[0].SHA256, sha256sum)
		}

		if out[0].Data != base64.StdEncoding.EncodeToString([]byte(data)) {
			t.Fatalf("invalid data: %s != %s", out[0].Data, data)
		}

		if data != "" && !bytes.Contains(readFile(path, t), []byte(data)) {
			t.Fatalf("invalid data")
		}
	}
}

func TestVerifyAdditionalData(t *testing.T) {
	tests := []string{
		"line1",
		"line1\nline2\nline3",
		"foo" + strings.Repeat("ABC", 1024),
		"foo" + strings.Repeat("ABC", 1024*64),
	}

	for _, data := range tests {
		path, sha256sum := seal([]byte(data), false, t)

		goodData, goodSha256 := unseal(path, false, t)
		if goodSha256 != sha256sum {
			t.Fatalf("invalid sha256: %s != %s", goodSha256, sha256sum)
		}

		if !bytes.Equal(goodData, []byte(data)) {
			t.Fatalf("invalid data: %s != %s", goodData, data)
		}

		outf, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600) // #nosec G304
		if err != nil {
			t.Fatalf("%v", err)
		}

		_, err = outf.Write([]byte("\x00"))
		if err != nil {
			t.Fatalf("%v", err)
		}

		err = outf.Close()
		if err != nil {
			t.Fatalf("%v", err)
		}

		inf, err := os.Open(path) // #nosec G304
		if err != nil {
			t.Fatalf("%v", err)
		}

		keyring, err := blob.ReadKeyring(privKey(t), pubKeys(t))
		if err != nil {
			t.Fatalf("%v", err)
		}

		_, err = blob.NewReader(inf, &blob.Options{
			Type:      "cryptor-test",
			Keyring:   keyring,
			Encrypted: false,
		})
		if !errors.Is(err, iofs.ErrInvalidSize) {
			t.Fatalf("expected invalid size error")

		}

		err = inf.Close()
		if err != nil {
			t.Fatalf("%v", err)
		}
	}
}

func TestVerifyOverwrittenData(t *testing.T) {
	tests := []string{
		"line1",
		"line1\nline2\nline3",
		"foo" + strings.Repeat("ABC", 1024),
		"foo" + strings.Repeat("ABC", 1024*64),
	}

	for _, data := range tests {
		path, sha256sum := seal([]byte(data), false, t)

		goodData, goodSha256 := unseal(path, false, t)
		if goodSha256 != sha256sum {
			t.Fatalf("invalid sha256: %s != %s", goodSha256, sha256sum)
		}

		if !bytes.Equal(goodData, []byte(data)) {
			t.Fatalf("invalid data: %s != %s", goodData, data)
		}

		outf, err := os.OpenFile(path, os.O_RDWR, 0600) // #nosec G304
		if err != nil {
			t.Fatalf("%v", err)
		}

		_, err = outf.Seek(-1, io.SeekEnd)
		if err != nil {
			t.Fatalf("%v", err)
		}

		_, err = outf.Write([]byte("\x00"))
		if err != nil {
			t.Fatalf("%v", err)
		}

		err = outf.Close()
		if err != nil {
			t.Fatalf("%v", err)
		}

		inf, err := os.Open(path) // #nosec G304
		if err != nil {
			t.Fatalf("%v", err)
		}

		keyring, err := blob.ReadKeyring(privKey(t), pubKeys(t))
		if err != nil {
			t.Fatalf("%v", err)
		}

		_, err = blob.NewReader(inf, &blob.Options{
			Type:      "cryptor-test",
			Keyring:   keyring,
			Encrypted: false,
		})

		if !errors.Is(err, hasher.ErrInvalidHash) {
			t.Fatalf("expected invalid hash error")

		}

		err = inf.Close()
		if err != nil {
			t.Fatalf("%v", err)
		}
	}
}

func seal(data []byte, encrypted bool, t *testing.T) (string, string) {
	path := filepath.Join(t.TempDir(), "data")
	f, err := os.Create(path) // #nosec G304
	if err != nil {
		t.Fatalf("%v", err)
	}

	keyring, err := blob.ReadKeyring(privKey(t), pubKeys(t))
	if err != nil {
		t.Fatalf("%v", err)
	}

	writer, err := blob.NewWriter(f, &blob.Options{
		Type:      "cryptor-test",
		Keyring:   keyring,
		Encrypted: encrypted,
	})
	if err != nil {
		t.Fatalf("%v", err)
	}

	_, err = writer.Write(data)
	if err != nil {
		t.Fatalf("%v", err)
	}

	err = writer.Close()
	if err != nil {
		t.Fatalf("%v", err)
	}

	err = f.Close()
	if err != nil {
		t.Fatalf("%v", err)
	}

	sha256sum := sha256.Sum256(data)
	return path, hex.EncodeToString(sha256sum[:])
}

func unseal(path string, encrypted bool, t *testing.T) ([]byte, string) {
	f, err := os.Open(path) // #nosec G304
	if err != nil {
		t.Fatalf("%v", err)
	}

	keyring, err := blob.ReadKeyring(privKey(t), pubKeys(t))
	if err != nil {
		t.Fatalf("%v", err)
	}

	reader, err := blob.NewReader(f, &blob.Options{
		Type:      "cryptor-test",
		Keyring:   keyring,
		Encrypted: encrypted,
	})
	if err != nil {
		t.Fatalf("%v", err)
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, reader)
	if err != nil {
		t.Fatalf("%v", err)
	}

	sha256sum := sha256.Sum256(buf.Bytes())
	return buf.Bytes(), hex.EncodeToString(sha256sum[:])
}

func unsealpy(file string, encrypted bool, t *testing.T) []output {
	cmd := []string{
		filepath.Join(testDir(t), "unseal.py"),
		"--privkey", privKey(t),
		"--in", file,
	}
	if !encrypted {
		cmd = append(cmd, "--signed-only")
	}

	decrypt := exec.Command(cmd[0], cmd[1:]...) // #nosec G204
	stdout := bytes.Buffer{}
	stderr := bytes.Buffer{}
	decrypt.Stdout = &stdout
	decrypt.Stderr = &stderr

	err := decrypt.Run()
	if err != nil {
		t.Fatalf("stdout: %s\nstderr: %s\n%v", stdout.String(), stderr.String(), err)
	}

	var out []output
	err = json.Unmarshal(stdout.Bytes(), &out)
	if err != nil {
		t.Fatalf("%v", err)
	}

	return out
}

func privKey(t *testing.T) string {
	tests := testDir(t)
	return filepath.Join(tests, "data", "test.priv")
}

func pubKeys(t *testing.T) []string {
	tests := testDir(t)
	return []string{filepath.Join(tests, "data", "test.pub")}
}

func testDir(t *testing.T) string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("unable to get caller")
	}
	return filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(file))), "tests")
}

func readFile(path string, t *testing.T) []byte {
	data, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		t.Fatalf("%v", err)
	}
	return data
}
