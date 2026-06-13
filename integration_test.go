package hap

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"

	"golang.org/x/crypto/curve25519"
	"tinygo.org/x/bluetooth"
)

// mockAccessory implements conn by simulating an unpaired HomeKit accessory: it runs the
// accessory side of pair-setup and pair-verify and then acts as the encrypted endpoint for
// characteristic writes. It assumes a large MTU so every PDU is a single fragment, keeping
// the simulation focused on protocol logic rather than fragment reassembly (covered by
// pdu_test). It lets us validate the controller's state machines end-to-end without a real
// device or setup code.
type mockAccessory struct {
	t        *testing.T
	password string

	id   string
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey

	pairings map[string]ed25519.PublicKey // controller id -> LTPK, from pair-setup M5

	srv         *srpServer
	srpK        []byte
	setupEncKey []byte

	verifyEphPub []byte
	verifyShared []byte
	verifyEncKey []byte
	controllerEph []byte // controller ephemeral pub from verify M1

	secured          bool
	sessReadKey      []byte // accessory decrypts controller->accessory
	sessWriteKey     []byte // accessory encrypts accessory->controller
	sessReadCounter  uint64
	sessWriteCounter uint64

	pending map[bluetooth.UUID][]byte
	tid     byte

	writes map[bluetooth.UUID][]byte // captured characteristic values
}

func newMockAccessory(t *testing.T, password string) *mockAccessory {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("accessory keygen: %v", err)
	}
	return &mockAccessory{
		t:        t,
		password: password,
		id:       "00:11:22:33:44:55",
		pub:      pub,
		priv:     priv,
		pairings: map[string]ed25519.PublicKey{},
		pending:  map[bluetooth.UUID][]byte{},
		writes:   map[bluetooth.UUID][]byte{},
	}
}

// --- conn implementation ---

func (m *mockAccessory) IID(charUUID bluetooth.UUID) (uint16, error) { return 0x0033, nil }
func (m *mockAccessory) nextTID() byte                               { m.tid++; return m.tid }
func (m *mockAccessory) fragmentSize() int                           { return 512 }

func (m *mockAccessory) writeFragment(charUUID bluetooth.UUID, data []byte) error {
	switch charUUID {
	case CharPairSetup, CharPairVerify:
		_, tid, body, err := decodeRequestPDU(data)
		if err != nil {
			return err
		}
		respTLV, err := m.handlePairing(charUUID, body)
		if err != nil {
			return err
		}
		m.pending[charUUID] = encodeResponse(tid, 0, tlvs{}.add(hapParamValue, respTLV).encode())
	default: // an encrypted session write
		if !m.secured {
			return fmt.Errorf("mock: unexpected write to %s before session established", charUUID)
		}
		plain, err := chachaOpen(m.sessReadKey, chachaNonce(m.sessReadCounter), data)
		if err != nil {
			return err
		}
		m.sessReadCounter++
		_, rtid, wbody, err := decodeRequestPDU(plain)
		if err != nil {
			return err
		}
		if value, ok := mustTLV(m.t, wbody).first(hapParamValue); ok {
			m.writes[charUUID] = value
		}
		resp := encodeResponse(rtid, 0, nil)
		ct, err := chachaSeal(m.sessWriteKey, chachaNonce(m.sessWriteCounter), resp)
		if err != nil {
			return err
		}
		m.sessWriteCounter++
		m.pending[charUUID] = ct
	}
	return nil
}

func (m *mockAccessory) readFragment(charUUID bluetooth.UUID) ([]byte, error) {
	resp, ok := m.pending[charUUID]
	if !ok {
		return nil, fmt.Errorf("mock: no pending response for %s", charUUID)
	}
	delete(m.pending, charUUID)
	return resp, nil
}

// --- accessory pairing logic ---

func (m *mockAccessory) handlePairing(charUUID bluetooth.UUID, reqBody []byte) ([]byte, error) {
	value, err := bleValue(reqBody)
	if err != nil {
		return nil, err
	}
	req := mustTLV(m.t, value)
	state, _ := req.firstByte(tlvState)
	if charUUID == CharPairSetup {
		return m.handlePairSetup(state, req)
	}
	return m.handlePairVerify(state, req)
}

func (m *mockAccessory) handlePairSetup(state byte, req tlvs) ([]byte, error) {
	switch state {
	case stateM1:
		m.srv = newSRPServer(m.password)
		return tlvs{}.addByte(tlvState, stateM2).
			add(tlvSalt, m.srv.salt).
			add(tlvPublicKey, pad(m.srv.B, srpByteLen())).encode(), nil
	case stateM3:
		// The controller already sends A padded to N's length, so use it as-is.
		A, _ := req.first(tlvPublicKey)
		m.srpK = m.srv.sessionKey(A)
		m.setupEncKey = hkdfPairSetupEncrypt.derive(m.srpK)
		// Server proof M2 = H(PAD(A) | clientProof | K).
		clientProof, _ := req.first(tlvProof)
		serverProof := sha512Sum(A, clientProof, m.srpK)
		return tlvs{}.addByte(tlvState, stateM4).add(tlvProof, serverProof).encode(), nil
	case stateM5:
		enc, _ := req.first(tlvEncryptedData)
		dec, err := chachaOpen(m.setupEncKey, pairingNonce("PS-Msg05"), enc)
		if err != nil {
			return nil, err
		}
		sub := mustTLV(m.t, dec)
		ctrlID, _ := sub.first(tlvIdentifier)
		ctrlPub, _ := sub.first(tlvPublicKey)
		ctrlSig, _ := sub.first(tlvSignature)
		ctrlInfo := concat(hkdfPairSetupController.derive(m.srpK), ctrlID, ctrlPub)
		if !ed25519.Verify(ed25519.PublicKey(ctrlPub), ctrlInfo, ctrlSig) {
			return nil, fmt.Errorf("mock: controller signature invalid in M5")
		}
		m.pairings[string(ctrlID)] = append(ed25519.PublicKey(nil), ctrlPub...)
		// M6: our identity, signed.
		accInfo := concat(hkdfPairSetupAccessory.derive(m.srpK), []byte(m.id), m.pub)
		sub6 := tlvs{}.
			add(tlvIdentifier, []byte(m.id)).
			add(tlvPublicKey, m.pub).
			add(tlvSignature, ed25519.Sign(m.priv, accInfo)).encode()
		encM6, err := chachaSeal(m.setupEncKey, pairingNonce("PS-Msg06"), sub6)
		if err != nil {
			return nil, err
		}
		return tlvs{}.addByte(tlvState, stateM6).add(tlvEncryptedData, encM6).encode(), nil
	}
	return nil, fmt.Errorf("mock: unexpected pair-setup state %d", state)
}

func (m *mockAccessory) handlePairVerify(state byte, req tlvs) ([]byte, error) {
	switch state {
	case stateM1:
		m.controllerEph, _ = req.first(tlvPublicKey)
		var ephPriv [32]byte
		if _, err := rand.Read(ephPriv[:]); err != nil {
			return nil, err
		}
		ephPub, err := curve25519.X25519(ephPriv[:], curve25519.Basepoint)
		if err != nil {
			return nil, err
		}
		m.verifyEphPub = ephPub
		m.verifyShared, err = curve25519.X25519(ephPriv[:], m.controllerEph)
		if err != nil {
			return nil, err
		}
		m.verifyEncKey = hkdfPairVerifyEncrypt.derive(m.verifyShared)
		accInfo := concat(ephPub, []byte(m.id), m.controllerEph)
		sub := tlvs{}.add(tlvIdentifier, []byte(m.id)).add(tlvSignature, ed25519.Sign(m.priv, accInfo)).encode()
		encM2, err := chachaSeal(m.verifyEncKey, pairingNonce("PV-Msg02"), sub)
		if err != nil {
			return nil, err
		}
		return tlvs{}.addByte(tlvState, stateM2).add(tlvPublicKey, ephPub).add(tlvEncryptedData, encM2).encode(), nil
	case stateM3:
		enc, _ := req.first(tlvEncryptedData)
		dec, err := chachaOpen(m.verifyEncKey, pairingNonce("PV-Msg03"), enc)
		if err != nil {
			return nil, err
		}
		sub := mustTLV(m.t, dec)
		ctrlID, _ := sub.first(tlvIdentifier)
		ctrlSig, _ := sub.first(tlvSignature)
		ctrlLTPK, ok := m.pairings[string(ctrlID)]
		if !ok {
			return nil, fmt.Errorf("mock: unknown controller %q in verify M3", ctrlID)
		}
		ctrlInfo := concat(m.controllerEph, ctrlID, m.verifyEphPub)
		if !ed25519.Verify(ctrlLTPK, ctrlInfo, ctrlSig) {
			return nil, fmt.Errorf("mock: controller signature invalid in verify M3")
		}
		// Mirror the controller's key derivation (read/write swapped from its viewpoint).
		m.sessReadKey = hkdfControlWrite.derive(m.verifyShared)
		m.sessWriteKey = hkdfControlRead.derive(m.verifyShared)
		m.secured = true
		return tlvs{}.addByte(tlvState, stateM4).encode(), nil
	}
	return nil, fmt.Errorf("mock: unexpected pair-verify state %d", state)
}

// --- helpers ---

func mustTLV(t *testing.T, b []byte) tlvs {
	t.Helper()
	out, err := decodeTLV(b)
	if err != nil {
		t.Fatalf("decodeTLV: %v", err)
	}
	return out
}

// decodeRequestPDU parses a single-fragment request PDU into opcode, tid and body.
func decodeRequestPDU(buf []byte) (opcode, tid byte, body []byte, err error) {
	if len(buf) < 5 {
		return 0, 0, nil, fmt.Errorf("mock: request PDU too short (%d bytes)", len(buf))
	}
	opcode, tid = buf[1], buf[2]
	if len(buf) > 5 {
		bodyLen := int(buf[5]) | int(buf[6])<<8
		if 7+bodyLen > len(buf) {
			return 0, 0, nil, fmt.Errorf("mock: request PDU body length %d overruns %d-byte buffer", bodyLen, len(buf))
		}
		body = buf[7 : 7+bodyLen]
	}
	return opcode, tid, body, nil
}

func TestPairAndVerifyRoundTrip(t *testing.T) {
	const code = "31344659"
	acc := newMockAccessory(t, formatSetupCode(code))

	pd, err := pair(acc, code)
	if err != nil {
		t.Fatalf("pair: %v", err)
	}
	if pd.AccessoryID != acc.id {
		t.Errorf("AccessoryID = %q; want %q", pd.AccessoryID, acc.id)
	}
	if !bytes.Equal(pd.AccessoryLTPK, acc.pub) {
		t.Error("stored accessory LTPK does not match the accessory's key")
	}
	if _, ok := acc.pairings[pd.ControllerID]; !ok {
		t.Error("accessory did not record our controller pairing")
	}

	// Verify should round-trip and re-establish a session from the stored data.
	sess, err := verify(acc, pd)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !bytes.Equal(sess.writeKey, acc.sessReadKey) || !bytes.Equal(sess.readKey, acc.sessWriteKey) {
		t.Fatal("session keys disagree between controller and accessory")
	}

	// An encrypted characteristic write must decrypt to the expected value on the accessory.
	if err := sess.SetOn(true); err != nil {
		t.Fatalf("SetOn: %v", err)
	}
	if got := acc.writes[CharOn]; len(got) != 1 || got[0] != 1 {
		t.Errorf("accessory received On = % x; want 01", got)
	}
	if err := sess.SetHue(120); err != nil {
		t.Fatalf("SetHue: %v", err)
	}
	if got := acc.writes[CharHue]; !bytes.Equal(got, floatLE(120)) {
		t.Errorf("accessory received Hue = % x; want % x", got, floatLE(120))
	}
}

func TestPairWrongCodeRejected(t *testing.T) {
	acc := newMockAccessory(t, formatSetupCode("11111111"))
	if _, err := pair(acc, "22222222"); err == nil {
		t.Error("pair succeeded with the wrong setup code")
	}
}
