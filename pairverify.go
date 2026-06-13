package hap

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// Verify performs HAP pair-verify using previously stored PairingData and returns an
// authenticated, encrypted Session. It runs on every connection (pairing happens once;
// verifying happens each time) and proves both parties still hold their long-term keys.
func Verify(t *Transport, p PairingData) (*Session, error) {
	return verify(t, p)
}

func verify(c conn, p PairingData) (*Session, error) {
	if err := p.valid(); err != nil {
		return nil, err
	}

	// M1 -> M2: send our ephemeral X25519 public key; receive the accessory's plus an
	// encrypted proof of its identity.
	var ourPriv [32]byte
	if _, err := rand.Read(ourPriv[:]); err != nil {
		return nil, err
	}
	ourPub, err := curve25519.X25519(ourPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	m1 := tlvs{}.addByte(tlvState, stateM1).add(tlvPublicKey, ourPub).encode()
	m2, err := pairingExchange(c, CharPairVerify, m1)
	if err != nil {
		return nil, fmt.Errorf("pair-verify M1/M2: %w", err)
	}
	accPub, ok := m2.first(tlvPublicKey)
	if !ok {
		return nil, errors.New("hap: pair-verify M2 missing public key")
	}
	encM2, ok := m2.first(tlvEncryptedData)
	if !ok {
		return nil, errors.New("hap: pair-verify M2 missing encrypted data")
	}

	shared, err := curve25519.X25519(ourPriv[:], accPub)
	if err != nil {
		return nil, err
	}
	encryptKey := hkdfPairVerifyEncrypt.derive(shared)

	dec, err := chachaOpen(encryptKey, pairingNonce("PV-Msg02"), encM2)
	if err != nil {
		return nil, err
	}
	sub2, err := decodeTLV(dec)
	if err != nil {
		return nil, err
	}
	accID, ok1 := sub2.first(tlvIdentifier)
	accSig, ok2 := sub2.first(tlvSignature)
	if !ok1 || !ok2 {
		return nil, errors.New("hap: pair-verify M2 sub-TLV incomplete")
	}
	if string(accID) != p.AccessoryID {
		return nil, fmt.Errorf("hap: accessory identity %q does not match paired %q", accID, p.AccessoryID)
	}
	// The accessory signs accessoryPub || accessoryID || ourPub with its long-term key.
	accInfo := concat(accPub, accID, ourPub)
	if !ed25519.Verify(ed25519.PublicKey(p.AccessoryLTPK), accInfo, accSig) {
		return nil, errors.New("hap: accessory signature invalid in pair-verify M2")
	}

	// M3 -> M4: prove our identity by signing ourPub || controllerID || accessoryPub.
	ctrlInfo := concat(ourPub, []byte(p.ControllerID), accPub)
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(p.ControllerLTSK), ctrlInfo)
	sub3 := tlvs{}.add(tlvIdentifier, []byte(p.ControllerID)).add(tlvSignature, sig).encode()
	encM3, err := chachaSeal(encryptKey, pairingNonce("PV-Msg03"), sub3)
	if err != nil {
		return nil, err
	}
	m3 := tlvs{}.addByte(tlvState, stateM3).add(tlvEncryptedData, encM3).encode()
	if _, err := pairingExchange(c, CharPairVerify, m3); err != nil {
		return nil, fmt.Errorf("pair-verify M3/M4: %w", err)
	}

	// Derive the per-direction session keys from the shared secret.
	return newSession(c, hkdfControlWrite.derive(shared), hkdfControlRead.derive(shared)), nil
}
