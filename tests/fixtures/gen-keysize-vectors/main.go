// Generates tests/fixtures/gocrypt_keysize_vectors.json: GoCrypt values for the
// AES-GCM key sizes 16, 24 and 32 (AES-128, AES-192, AES-256).
//
// The main fixture, gocrypt_vectors.json, is a verbatim copy of RustCrypt's and
// has a single non-default key size (16). This one covers all three.
//
//   - "vectors": written by GoCrypt's own Encrypt with a random salt and nonce.
//     PHPCrypt must decrypt them.
//   - "fixed": computed here with a fixed salt and nonce, from the same
//     primitives GoCrypt uses (PBKDF2-HMAC-SHA256, AES-GCM), and each one is
//     checked by decrypting it with GoCrypt itself before it is written.
//     PHPCrypt must reproduce them byte for byte.
//
// Any value given as an argument "keySize:iterations:saltSize:plaintext:base64"
// is decrypted with GoCrypt and must give that plaintext. That is how values
// written by PHPCrypt were checked against GoCrypt.
//
// To regenerate:
//
//	go mod init gen-keysize-vectors
//	go get github.com/farizfadian/gocrypt@v1.0.0
//	go run . > ../gocrypt_keysize_vectors.json
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/farizfadian/gocrypt"
)

const password = "phpcrypt-keysize-2026"

var plaintexts = []string{"hello", "Selamat pagi, PHPCrypt 🐘"}

type vector struct {
	KeySize    int    `json:"key_size"`
	Iterations int    `json:"iterations"`
	SaltSize   int    `json:"salt_size"`
	Plaintext  string `json:"plaintext"`
	Encoded    string `json:"encoded"`
}

type fixedVector struct {
	KeySize    int    `json:"key_size"`
	Iterations int    `json:"iterations"`
	SaltHex    string `json:"salt_hex"`
	NonceHex   string `json:"nonce_hex"`
	Plaintext  string `json:"plaintext"`
	Encoded    string `json:"encoded"`
}

type fixture struct {
	Description   string        `json:"description"`
	Generator     string        `json:"generator"`
	GocryptModule string        `json:"gocrypt_module"`
	GeneratedAt   string        `json:"generated_at"`
	Password      string        `json:"password"`
	Vectors       []vector      `json:"vectors"`
	Fixed         []fixedVector `json:"fixed"`
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func encryptor(keySize, iterations, saltSize int) *gocrypt.Encryptor {
	e, err := gocrypt.NewEncryptor(password,
		gocrypt.WithKeySize(keySize), gocrypt.WithIterations(iterations), gocrypt.WithSaltSize(saltSize))
	must(err)
	return e
}

// pbkdf2 is PBKDF2-HMAC-SHA256 (RFC 8018).
func pbkdf2(pw, salt []byte, iterations, keyLen int) []byte {
	var out []byte
	for block := uint32(1); len(out) < keyLen; block++ {
		mac := hmac.New(sha256.New, pw)
		mac.Write(salt)
		var counter [4]byte
		binary.BigEndian.PutUint32(counter[:], block)
		mac.Write(counter[:])
		u := mac.Sum(nil)
		t := append([]byte(nil), u...)
		for i := 1; i < iterations; i++ {
			mac = hmac.New(sha256.New, pw)
			mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

func encryptFixed(salt, nonce []byte, iterations, keySize int, plaintext string) string {
	block, err := aes.NewCipher(pbkdf2([]byte(password), salt, iterations, keySize))
	must(err)
	gcm, err := cipher.NewGCM(block)
	must(err)
	combined := append(append([]byte(nil), salt...), nonce...)
	combined = gcm.Seal(combined, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(combined)
}

func main() {
	// Check values written by another implementation.
	for _, arg := range os.Args[1:] {
		parts := strings.SplitN(arg, ":", 5)
		if len(parts) != 5 {
			must(fmt.Errorf("bad argument %q", arg))
		}
		keySize, _ := strconv.Atoi(parts[0])
		iterations, _ := strconv.Atoi(parts[1])
		saltSize, _ := strconv.Atoi(parts[2])
		got, err := encryptor(keySize, iterations, saltSize).Decrypt(parts[4])
		must(err)
		if got != parts[3] {
			must(fmt.Errorf("key size %d: got %q, want %q", keySize, got, parts[3]))
		}
		fmt.Fprintf(os.Stderr, "GoCrypt decrypted the key size %d value: OK\n", keySize)
	}
	if len(os.Args) > 1 {
		return
	}

	out := fixture{
		Description:   "GoCrypt values for AES-GCM key sizes 16, 24 and 32. See gen-keysize-vectors/main.go.",
		Generator:     "tests/fixtures/gen-keysize-vectors/main.go",
		GocryptModule: "github.com/farizfadian/gocrypt v1.0.0",
		GeneratedAt:   "2026-11-19",
		Password:      password,
	}

	salt, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	nonce, _ := hex.DecodeString("a1a2a3a4a5a6a7a8a9aaabac")

	for _, keySize := range []int{16, 24, 32} {
		for _, pt := range plaintexts {
			e := encryptor(keySize, 1000, 16)
			encoded, err := e.Encrypt(pt)
			must(err)
			got, err := e.Decrypt(encoded)
			must(err)
			if got != pt {
				must(fmt.Errorf("gocrypt round trip mismatch for key size %d", keySize))
			}
			out.Vectors = append(out.Vectors, vector{keySize, 1000, 16, pt, encoded})

			fixed := encryptFixed(salt, nonce, 1000, keySize, pt)
			got, err = e.Decrypt(fixed)
			must(err)
			if got != pt {
				must(fmt.Errorf("gocrypt does not accept the fixed value for key size %d", keySize))
			}
			out.Fixed = append(out.Fixed, fixedVector{keySize, 1000, hex.EncodeToString(salt), hex.EncodeToString(nonce), pt, fixed})
		}
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	must(enc.Encode(out))
}
