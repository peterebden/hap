package hap

import (
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"math/big"
)

// SRP-6a as HomeKit uses it during pair-setup (HAP spec §5.6): SHA-512 hashing over the
// 3072-bit RFC-5054 group, username "Pair-Setup", password = the device setup code. The
// controller is the SRP client. Padding conventions (PAD to the byte length of N, salt
// to 16 bytes) follow aiohomekit's implementation, which interoperates with real
// accessories; TestSRPGroupConstant pins the derived k against HomeKit's known value.

const srpUsername = "Pair-Setup"

// srpGroupHex is the 3072-bit modulus N (RFC 3526 group 15); the generator g is 5.
const srpGroupHex = "" +
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
	"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
	"83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
	"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
	"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
	"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
	"15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" +
	"ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
	"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" +
	"F12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
	"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" +
	"43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"

var (
	srpN = mustHexInt(srpGroupHex)
	srpG = big.NewInt(5)
)

func mustHexInt(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("hap: invalid SRP group constant")
	}
	return n
}

// srpByteLen is the length in bytes of N; values are left-padded to it before hashing.
func srpByteLen() int { return (srpN.BitLen() + 7) / 8 }

// pad left-pads x's big-endian bytes to n bytes.
func pad(x *big.Int, n int) []byte {
	b := x.Bytes()
	if len(b) >= n {
		return b
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

func sha512Sum(parts ...[]byte) []byte {
	h := sha512.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

func xorBytes(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// srpMultiplier returns k = H(N | PAD(g)). It is constant for the fixed HomeKit group.
func srpMultiplier() *big.Int {
	n := srpByteLen()
	return new(big.Int).SetBytes(sha512Sum(pad(srpN, n), pad(srpG, n)))
}

// srpClient holds the controller's SRP state across the pair-setup exchange.
type srpClient struct {
	password string
	a        *big.Int // private ephemeral
	A        *big.Int // public ephemeral, g^a mod N
	k        []byte   // shared session key, set by computeProof
}

// newSRPClient creates a client with a fresh random ephemeral key. The password is the
// setup code; callers pass it already formatted (see formatSetupCode).
func newSRPClient(password string) (*srpClient, error) {
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		return nil, err
	}
	a := new(big.Int).SetBytes(priv)
	A := new(big.Int).Exp(srpG, a, srpN)
	if A.Sign() == 0 {
		return nil, fmt.Errorf("hap: degenerate SRP public key, retry")
	}
	return &srpClient{password: password, a: a, A: A}, nil
}

// publicKey returns the client public ephemeral A, padded to N's length for the wire.
func (c *srpClient) publicKey() []byte { return pad(c.A, srpByteLen()) }

// computeProof consumes the salt and server public key B from M2, derives the shared
// session key, and returns the client proof M1 to send in M3.
func (c *srpClient) computeProof(salt, serverB []byte) (m1 []byte, err error) {
	n := srpByteLen()
	B := new(big.Int).SetBytes(serverB)
	if new(big.Int).Mod(B, srpN).Sign() == 0 {
		return nil, fmt.Errorf("hap: server SRP public key is zero mod N")
	}

	u := new(big.Int).SetBytes(sha512Sum(pad(c.A, n), pad(B, n)))
	if u.Sign() == 0 {
		return nil, fmt.Errorf("hap: SRP u parameter is zero")
	}
	// x = H(PAD(salt,16) | H(username:password))
	inner := sha512Sum([]byte(srpUsername + ":" + c.password))
	x := new(big.Int).SetBytes(sha512Sum(pad(new(big.Int).SetBytes(salt), 16), inner))

	// S = (B - k*g^x) ^ (a + u*x) mod N
	k := srpMultiplier()
	gx := new(big.Int).Exp(srpG, x, srpN)
	base := new(big.Int).Sub(B, new(big.Int).Mod(new(big.Int).Mul(k, gx), srpN))
	base.Mod(base, srpN) // keep in [0,N)
	exp := new(big.Int).Add(c.a, new(big.Int).Mul(u, x))
	S := new(big.Int).Exp(base, exp, srpN)

	c.k = sha512Sum(pad(S, n)) // session key K = H(PAD(S))

	// M1 = H( H(N) xor H(g) | H(username) | PAD(salt,16) | PAD(A) | PAD(B) | K )
	hN := sha512Sum(srpN.Bytes())
	hG := sha512Sum(srpG.Bytes())
	m1 = sha512Sum(
		xorBytes(hN, hG),
		sha512Sum([]byte(srpUsername)),
		pad(new(big.Int).SetBytes(salt), 16),
		pad(c.A, n),
		pad(B, n),
		c.k,
	)
	return m1, nil
}

// verifyServerProof checks the accessory's M2 proof from pair-setup M4:
// expected = H(PAD(A) | M1 | K).
func (c *srpClient) verifyServerProof(m1, serverProof []byte) bool {
	expected := sha512Sum(pad(c.A, srpByteLen()), m1, c.k)
	return subtleEqual(expected, serverProof)
}

// sessionKey returns the shared SRP key K (valid only after computeProof).
func (c *srpClient) sessionKey() []byte { return c.k }
