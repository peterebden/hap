package hap

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"
)

// The SRP multiplier k = H(N | PAD(g)) is constant for HomeKit's fixed group. Pinning it
// against the value HomeKit uses validates N, the padding, and the SHA-512 wiring all at
// once — the conventions we can't otherwise check without a real accessory.
func TestSRPGroupConstant(t *testing.T) {
	const want = "a9c2e2559bf0ebb53f0cbbf62282906bede7f2182f00678211fbd5bde5b285033a4993503b87397f9be5ec02080fedbc0835587ad039060879b8621e8c3659e0"
	got := hex.EncodeToString(pad(srpMultiplier(), 64))
	if got != want {
		t.Errorf("k = %s\nwant %s", got, want)
	}
}

// srpServer is a minimal SRP-6a server used only to exercise the client end-to-end: if
// both sides derive the same key and the proofs verify, the client math is internally
// consistent.
type srpServer struct {
	salt, v   []byte
	b, B, key *big.Int
}

func newSRPServer(password string) *srpServer {
	salt := []byte("0123456789abcdef") // 16 bytes
	n := srpByteLen()
	inner := sha512Sum([]byte(srpUsername + ":" + password))
	x := new(big.Int).SetBytes(sha512Sum(pad(new(big.Int).SetBytes(salt), 16), inner))
	v := new(big.Int).Exp(srpG, x, srpN)

	b := new(big.Int).SetBytes(bytes.Repeat([]byte{0x42}, 32)) // fixed for determinism
	k := srpMultiplier()
	// B = (k*v + g^b) mod N
	B := new(big.Int).Mod(new(big.Int).Add(new(big.Int).Mul(k, v), new(big.Int).Exp(srpG, b, srpN)), srpN)
	return &srpServer{salt: salt, v: pad(v, n), b: b, B: B}
}

// session computes the server's shared key given the client public A.
func (s *srpServer) sessionKey(clientA []byte) []byte {
	n := srpByteLen()
	A := new(big.Int).SetBytes(clientA)
	u := new(big.Int).SetBytes(sha512Sum(pad(A, n), pad(s.B, n)))
	v := new(big.Int).SetBytes(s.v)
	// S = (A * v^u) ^ b mod N
	base := new(big.Int).Mod(new(big.Int).Mul(A, new(big.Int).Exp(v, u, srpN)), srpN)
	S := new(big.Int).Exp(base, s.b, srpN)
	return sha512Sum(pad(S, n))
}

func TestSRPClientServerRoundTrip(t *testing.T) {
	const password = "123-45-678"
	server := newSRPServer(password)

	client, err := newSRPClient(password)
	if err != nil {
		t.Fatalf("newSRPClient: %v", err)
	}
	m1, err := client.computeProof(server.salt, pad(server.B, srpByteLen()))
	if err != nil {
		t.Fatalf("computeProof: %v", err)
	}

	// Both sides must derive the same session key.
	if !bytes.Equal(client.sessionKey(), server.sessionKey(client.publicKey())) {
		t.Fatal("client and server derived different session keys")
	}

	// The server proof the client expects: H(PAD(A) | M1 | K).
	serverProof := sha512Sum(client.publicKey(), m1, client.sessionKey())
	if !client.verifyServerProof(m1, serverProof) {
		t.Error("verifyServerProof rejected a valid server proof")
	}
	if client.verifyServerProof(m1, bytes.Repeat([]byte{0}, 64)) {
		t.Error("verifyServerProof accepted an invalid server proof")
	}
}

func TestSRPWrongPasswordDiffersKey(t *testing.T) {
	server := newSRPServer("111-11-111")
	client, err := newSRPClient("222-22-222")
	if err != nil {
		t.Fatalf("newSRPClient: %v", err)
	}
	if _, err := client.computeProof(server.salt, pad(server.B, srpByteLen())); err != nil {
		t.Fatalf("computeProof: %v", err)
	}
	if bytes.Equal(client.sessionKey(), server.sessionKey(client.publicKey())) {
		t.Error("keys matched despite different passwords")
	}
}
