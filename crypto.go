package hap

import (
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// subtleEqual reports whether two byte slices are equal, in constant time.
func subtleEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// hkdfSHA512 derives a 32-byte key from the input keying material using HKDF-SHA-512,
// the construction HomeKit uses throughout pairing.
func hkdfSHA512(ikm, salt, info []byte) []byte {
	out := make([]byte, 32)
	r := hkdf.New(sha512.New, ikm, salt, info)
	if _, err := io.ReadFull(r, out); err != nil {
		panic(err) // reading 32 bytes from HKDF cannot fail
	}
	return out
}

// HKDF salt/info pairs used during pairing (HAP spec §5.6, §5.7).
var (
	hkdfPairSetupEncrypt    = hkdfParams{"Pair-Setup-Encrypt-Salt", "Pair-Setup-Encrypt-Info"}
	hkdfPairSetupController = hkdfParams{"Pair-Setup-Controller-Sign-Salt", "Pair-Setup-Controller-Sign-Info"}
	hkdfPairSetupAccessory  = hkdfParams{"Pair-Setup-Accessory-Sign-Salt", "Pair-Setup-Accessory-Sign-Info"}
	hkdfPairVerifyEncrypt   = hkdfParams{"Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info"}
	// Session keys after pair-verify; "Read" is accessory→controller, "Write" is controller→accessory.
	hkdfControlRead  = hkdfParams{"Control-Salt", "Control-Read-Encryption-Key"}
	hkdfControlWrite = hkdfParams{"Control-Salt", "Control-Write-Encryption-Key"}
)

type hkdfParams struct{ salt, info string }

func (p hkdfParams) derive(ikm []byte) []byte {
	return hkdfSHA512(ikm, []byte(p.salt), []byte(p.info))
}

// chachaNonce builds the 12-byte HAP nonce: 4 zero bytes followed by an 8-byte
// little-endian counter (used both for the fixed pairing nonces and session counters).
func chachaNonce(counter uint64) []byte {
	nonce := make([]byte, chacha20poly1305.NonceSize) // 12 bytes
	binary.LittleEndian.PutUint64(nonce[4:], counter)
	return nonce
}

// pairingNonce builds a 12-byte nonce from one of the fixed pairing labels such as
// "PS-Msg05": the ASCII label right-aligned in a zero-padded 12-byte block.
func pairingNonce(label string) []byte {
	nonce := make([]byte, chacha20poly1305.NonceSize)
	copy(nonce[chacha20poly1305.NonceSize-len(label):], label)
	return nonce
}

// chachaSeal encrypts plaintext with ChaCha20-Poly1305 and no additional data.
func chachaSeal(key, nonce, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, nil), nil
}

// chachaOpen decrypts ciphertext (ciphertext||tag) with ChaCha20-Poly1305 and no
// additional data.
func chachaOpen(key, nonce, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("hap: decryption failed (wrong key or tampered data): %w", err)
	}
	return pt, nil
}
