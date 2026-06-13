package hap

import (
	"errors"
	"fmt"

	"tinygo.org/x/bluetooth"
)

// HAP pairing state values M1..M6 (HAP spec §5.6/§5.7).
const (
	stateM1 = 1
	stateM2 = 2
	stateM3 = 3
	stateM4 = 4
	stateM5 = 5
	stateM6 = 6
)

// Pairing method values for kTLVType_Method.
const (
	methodPairSetup  = 0
	methodPairVerify = 2
)

// HAP-BLE PDU body parameter types (HAP spec §7.3.3.1). A characteristic write/read body
// is itself a TLV: the value lives under hapParamValue, and hapParamReturnResponse asks
// the accessory to include the value in its response.
const (
	hapParamValue          = 0x01
	hapParamReturnResponse = 0x09
)

// bleBody wraps a payload as a HAP-BLE characteristic-write body: a return-response flag
// followed by the value parameter.
func bleBody(value []byte) []byte {
	return tlvs{}.addByte(hapParamReturnResponse, 1).add(hapParamValue, value).encode()
}

// bleValue extracts the HAP-Param-Value (0x01) from a HAP-BLE response body.
func bleValue(body []byte) ([]byte, error) {
	t, err := decodeTLV(body)
	if err != nil {
		return nil, err
	}
	v, ok := t.first(hapParamValue)
	if !ok {
		return nil, errors.New("hap: response body missing value parameter")
	}
	return v, nil
}

// pairError maps a kTLVType_Error code (HAP spec Table 5-5) to a descriptive Go error.
func pairError(code byte) error {
	switch code {
	case 0x02:
		return errors.New("hap: authentication error (wrong setup code)")
	case 0x03:
		return errors.New("hap: backoff (too many attempts; wait before retrying)")
	case 0x04:
		return errors.New("hap: max peers (accessory pairing slots full)")
	case 0x05:
		return errors.New("hap: max tries (too many incorrect setup codes)")
	case 0x06:
		return errors.New("hap: unavailable (accessory already paired; reset it first)")
	case 0x07:
		return errors.New("hap: busy (accessory temporarily unavailable; retry)")
	default:
		return fmt.Errorf("hap: pairing error code 0x%02x", code)
	}
}

// pairingExchange sends one pairing message (a Characteristic Write whose body wraps the
// request TLV) to a pairing characteristic and returns the decoded response TLVs,
// surfacing a non-zero PDU status or kTLVType_Error as a Go error. Pairing messages are
// not session-encrypted; they carry their own TLV-level encryption.
func pairingExchange(c conn, charUUID bluetooth.UUID, request []byte) (tlvs, error) {
	iid, err := c.IID(charUUID)
	if err != nil {
		return nil, err
	}
	status, body, err := exchange(opCharWrite, c.nextTID(), iid, bleBody(request), c.fragmentSize(),
		func(b []byte) error { return c.writeFragment(charUUID, b) },
		func() ([]byte, error) { return c.readFragment(charUUID) })
	if err != nil {
		return nil, err
	}
	if status != 0 {
		return nil, fmt.Errorf("hap: pairing PDU returned status 0x%02x", status)
	}
	value, err := bleValue(body)
	if err != nil {
		return nil, err
	}
	resp, err := decodeTLV(value)
	if err != nil {
		return nil, err
	}
	if e, ok := resp.firstByte(tlvError); ok && e != 0 {
		return nil, pairError(e)
	}
	return resp, nil
}

// concat joins byte slices, used to build the signed info blocks in pairing.
func concat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
