package hap

import (
	"fmt"
	"strconv"
	"strings"

	"tinygo.org/x/bluetooth"
)

// Transport is the GATT plumbing the HAP protocol runs over. It caches the device's
// characteristics, resolves their HAP instance IDs from the instance-ID descriptor,
// and runs the fragment/reassemble loop for a single HAP request. The pairing and
// session layers sit on top of it.
type Transport struct {
	device bluetooth.Device
	chars  map[bluetooth.UUID]bluetooth.DeviceCharacteristic
	iids   map[bluetooth.UUID]uint16
	mtu    int
	tid    byte
}

// conn is the fragment-level GATT access the pairing and session layers run on. *Transport
// is the real implementation; tests provide an in-memory accessory that satisfies it.
type conn interface {
	IID(charUUID bluetooth.UUID) (uint16, error)
	nextTID() byte
	fragmentSize() int
	writeFragment(charUUID bluetooth.UUID, data []byte) error
	readFragment(charUUID bluetooth.UUID) ([]byte, error)
}

// nextTID returns a fresh transaction ID for the next request.
func (t *Transport) nextTID() byte {
	t.tid++
	return t.tid
}

// NewTransport discovers the device's services and characteristics up front so later
// lookups are cheap. The device must already be connected.
func NewTransport(device bluetooth.Device) (*Transport, error) {
	t := &Transport{
		device: device,
		chars:  map[bluetooth.UUID]bluetooth.DeviceCharacteristic{},
		iids:   map[bluetooth.UUID]uint16{},
		mtu:    23, // BLE default until we learn the negotiated value below
	}
	services, err := device.DiscoverServices(nil)
	if err != nil {
		return nil, fmt.Errorf("hap: discovering services: %w", err)
	}
	for _, svc := range services {
		chars, err := svc.DiscoverCharacteristics(nil)
		if err != nil {
			return nil, fmt.Errorf("hap: discovering characteristics of %s: %w", svc.UUID(), err)
		}
		for _, char := range chars {
			t.chars[char.UUID()] = char
			if t.mtu == 23 {
				if mtu, err := char.GetMTU(); err == nil && mtu > 23 {
					t.mtu = int(mtu)
				}
			}
		}
	}
	return t, nil
}

// fragmentSize is the most HAP payload we put in one GATT write. Reads come back whole
// because BlueZ does long reads for us, but the accessory does not accept ATT long writes
// (it answers a too-big WriteValue with ATT 0x0e), so a request larger than one ATT payload
// must be split into HAP continuation fragments — each its own Write Request of at most
// MTU-3 bytes — which the accessory reassembles. Hence we bound writes by the negotiated MTU.
func (t *Transport) fragmentSize() int {
	if t.mtu <= 23 {
		return 20
	}
	return t.mtu - 3
}

// IID returns the HAP instance ID of a characteristic, read once from its instance-ID
// descriptor and cached.
func (t *Transport) IID(charUUID bluetooth.UUID) (uint16, error) {
	if iid, ok := t.iids[charUUID]; ok {
		return iid, nil
	}
	char, ok := t.chars[charUUID]
	if !ok {
		return 0, fmt.Errorf("hap: characteristic %s not found on device", charUUID)
	}
	descs, err := char.DiscoverDescriptors([]bluetooth.UUID{descCharInstanceID})
	if err != nil {
		return 0, fmt.Errorf("hap: finding instance-ID descriptor for %s: %w", charUUID, err)
	}
	buf := make([]byte, 8)
	n, err := descs[0].Read(buf)
	if err != nil {
		return 0, fmt.Errorf("hap: reading instance-ID descriptor for %s: %w", charUUID, err)
	}
	if n < 2 {
		return 0, fmt.Errorf("hap: instance-ID descriptor for %s was %d bytes, want >=2", charUUID, n)
	}
	iid := uint16(buf[0]) | uint16(buf[1])<<8
	t.iids[charUUID] = iid
	return iid, nil
}

// writeFragment sends one GATT write (with response) of a single PDU fragment.
func (t *Transport) writeFragment(charUUID bluetooth.UUID, data []byte) error {
	char, ok := t.chars[charUUID]
	if !ok {
		return fmt.Errorf("hap: characteristic %s not found on device", charUUID)
	}
	_, err := char.Write(data)
	return annotateATTError(err)
}

// readFragment performs one GATT read, returning the whole response value. BlueZ does a
// long read under the hood and reports the full value length even when it exceeds the
// buffer we passed (copying only what fits), so when that happens we size the buffer to the
// reported length and read again to get the complete value.
func (t *Transport) readFragment(charUUID bluetooth.UUID) ([]byte, error) {
	char, ok := t.chars[charUUID]
	if !ok {
		return nil, fmt.Errorf("hap: characteristic %s not found on device", charUUID)
	}
	buf := make([]byte, 512)
	n, err := char.Read(buf)
	if err != nil {
		return nil, annotateATTError(err)
	}
	for n > len(buf) {
		buf = make([]byte, n)
		if n, err = char.Read(buf); err != nil {
			return nil, annotateATTError(err)
		}
	}
	return buf[:n], nil
}

// hapBLEStatusName names a HAP-BLE PDU status code (HAP spec Table 7-37). Accessories
// surface these at the GATT layer as ATT application errors (0x80 | status).
func hapBLEStatusName(status byte) string {
	switch status {
	case 0x00:
		return "success"
	case 0x01:
		return "unsupported PDU"
	case 0x02:
		return "max procedures"
	case 0x03:
		return "insufficient authorization (the accessory is likely already paired — reset or unpair it before running pair-setup)"
	case 0x04:
		return "invalid instance ID"
	case 0x05:
		return "insufficient authentication (run pair-verify to establish a session first)"
	case 0x06:
		return "invalid request"
	default:
		return fmt.Sprintf("unknown status 0x%02x", status)
	}
}

// annotateATTError makes BlueZ's opaque "ATT error: 0xNN" legible: codes 0x80–0x9F are the
// application-error range HAP uses to carry a PDU status code (0x80 | status), so we decode
// and explain them. Other errors pass through unchanged.
func annotateATTError(err error) error {
	if err == nil {
		return nil
	}
	const marker = "ATT error: 0x"
	s := err.Error()

	_, hex, ok := strings.Cut(s, marker)
	if !ok {
		return err
	}
	if len(hex) < 2 {
		return err
	}
	v, perr := strconv.ParseUint(hex[:2], 16, 8)
	if perr != nil {
		return err
	}
	if code := byte(v); code >= 0x80 && code <= 0x9f {
		return fmt.Errorf("%w — HAP %s", err, hapBLEStatusName(code-0x80))
	}
	return err
}
