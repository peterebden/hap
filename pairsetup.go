package hap

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
)

// Pair performs HAP pair-setup over the transport using the accessory's 8-digit setup
// code, returning PairingData to persist. The accessory must be in an unpaired (factory)
// state; one that is already paired rejects pair-setup with an "unavailable" error.
func Pair(t *Transport, setupCode string) (PairingData, error) {
	return pair(t, setupCode)
}

func pair(c conn, setupCode string) (PairingData, error) {
	code := formatSetupCode(setupCode)

	// M1 -> M2: start SRP. The accessory returns the salt and its SRP public key.
	m1 := tlvs{}.addByte(tlvState, stateM1).addByte(tlvMethod, methodPairSetup).encode()
	m2, err := pairingExchange(c, CharPairSetup, m1)
	if err != nil {
		return PairingData{}, fmt.Errorf("pair-setup M1/M2: %w", err)
	}
	salt, ok := m2.first(tlvSalt)
	if !ok {
		return PairingData{}, errors.New("hap: pair-setup M2 missing salt")
	}
	serverB, ok := m2.first(tlvPublicKey)
	if !ok {
		return PairingData{}, errors.New("hap: pair-setup M2 missing public key")
	}

	client, err := newSRPClient(code)
	if err != nil {
		return PairingData{}, err
	}
	proof, err := client.computeProof(salt, serverB)
	if err != nil {
		return PairingData{}, err
	}

	// M3 -> M4: send our SRP public key and proof; verify the accessory's proof in return.
	m3 := tlvs{}.addByte(tlvState, stateM3).add(tlvPublicKey, client.publicKey()).add(tlvProof, proof).encode()
	m4, err := pairingExchange(c, CharPairSetup, m3)
	if err != nil {
		return PairingData{}, fmt.Errorf("pair-setup M3/M4: %w", err)
	}
	serverProof, ok := m4.first(tlvProof)
	if !ok {
		return PairingData{}, errors.New("hap: pair-setup M4 missing proof")
	}
	if !client.verifyServerProof(proof, serverProof) {
		return PairingData{}, errors.New("hap: accessory proof invalid (wrong setup code?)")
	}

	// M5 -> M6: exchange long-term identities under the SRP-derived session key.
	K := client.sessionKey()
	encryptKey := hkdfPairSetupEncrypt.derive(K)

	controllerID, err := newPairingID()
	if err != nil {
		return PairingData{}, err
	}
	ctrlPub, ctrlPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return PairingData{}, err
	}
	// Sign iOSDeviceX || controllerID || controllerLTPK with our long-term key.
	ctrlInfo := concat(hkdfPairSetupController.derive(K), []byte(controllerID), ctrlPub)
	sub := tlvs{}.
		add(tlvIdentifier, []byte(controllerID)).
		add(tlvPublicKey, ctrlPub).
		add(tlvSignature, ed25519.Sign(ctrlPriv, ctrlInfo)).
		encode()
	enc, err := chachaSeal(encryptKey, pairingNonce("PS-Msg05"), sub)
	if err != nil {
		return PairingData{}, err
	}
	m5 := tlvs{}.addByte(tlvState, stateM5).add(tlvEncryptedData, enc).encode()
	m6, err := pairingExchange(c, CharPairSetup, m5)
	if err != nil {
		return PairingData{}, fmt.Errorf("pair-setup M5/M6: %w", err)
	}

	// Decrypt and verify the accessory's identity from M6.
	encM6, ok := m6.first(tlvEncryptedData)
	if !ok {
		return PairingData{}, errors.New("hap: pair-setup M6 missing encrypted data")
	}
	dec, err := chachaOpen(encryptKey, pairingNonce("PS-Msg06"), encM6)
	if err != nil {
		return PairingData{}, err
	}
	sub6, err := decodeTLV(dec)
	if err != nil {
		return PairingData{}, err
	}
	accID, ok1 := sub6.first(tlvIdentifier)
	accLTPK, ok2 := sub6.first(tlvPublicKey)
	accSig, ok3 := sub6.first(tlvSignature)
	if !ok1 || !ok2 || !ok3 {
		return PairingData{}, errors.New("hap: pair-setup M6 sub-TLV incomplete")
	}
	accInfo := concat(hkdfPairSetupAccessory.derive(K), accID, accLTPK)
	if len(accLTPK) != ed25519.PublicKeySize || !ed25519.Verify(ed25519.PublicKey(accLTPK), accInfo, accSig) {
		return PairingData{}, errors.New("hap: accessory signature invalid in pair-setup M6")
	}

	return PairingData{
		AccessoryID:    string(accID),
		AccessoryLTPK:  append([]byte(nil), accLTPK...),
		ControllerID:   controllerID,
		ControllerLTSK: ctrlPriv.Seed(),
	}, nil
}

// formatSetupCode normalises an 8-digit setup code to the dashed "XXX-XX-XXX" form that
// SRP uses as the password. Input with or without dashes is accepted; anything else is
// passed through so SRP fails with a clear authentication error.
func formatSetupCode(code string) string {
	digits := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, code)
	if len(digits) == 8 {
		return digits[0:3] + "-" + digits[3:5] + "-" + digits[5:8]
	}
	return code
}

// newPairingID generates a random controller pairing identifier (a UUID string). HAP only
// requires it to be a unique, stable string for the lifetime of the pairing.
func newPairingID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
