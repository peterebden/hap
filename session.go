package hap

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"time"

	"tinygo.org/x/bluetooth"
)

// Transient HAP-BLE statuses: this accessory has no dedicated "busy" code, so it answers a
// write it isn't ready for with Max-Procedures or Invalid-Request, which succeeds on retry.
const (
	statusMaxProcedures = 0x02
	statusInvalidReq    = 0x06
)

// writeRetries is how many times WriteCharacteristic re-sends a write that came back with a
// transient status before giving up.
const writeRetries = 6

// Session is an authenticated, encrypted connection to an accessory, established by
// Verify. Every HAP PDU is fragmented and then each fragment is encrypted with
// ChaCha20-Poly1305 under per-direction counters (HAP spec §7.4.7).
type Session struct {
	c            conn
	writeKey     []byte // controller -> accessory
	readKey      []byte // accessory -> controller
	writeCounter uint64
	readCounter  uint64
	// lastWritten records the last value we successfully wrote to each characteristic so we
	// can skip redundant writes (the accessory already holds the value, and needless writes
	// invite its transient rejections).
	lastWritten map[bluetooth.UUID][]byte
}

func newSession(c conn, writeKey, readKey []byte) *Session {
	return &Session{c: c, writeKey: writeKey, readKey: readKey, lastWritten: map[bluetooth.UUID][]byte{}}
}

// tagSize is the ChaCha20-Poly1305 authentication tag appended to each encrypted fragment.
const tagSize = 16

// request runs one encrypted HAP transaction: each plaintext fragment is sealed before
// the GATT write, and each response fragment is opened after the GATT read, advancing the
// independent send and receive counters.
func (s *Session) request(charUUID bluetooth.UUID, opcode byte, body []byte) (status byte, respBody []byte, err error) {
	iid, err := s.c.IID(charUUID)
	if err != nil {
		return 0, nil, err
	}
	fragSize := max(s.c.fragmentSize()-tagSize, 1) // leave room for the tag within one GATT op
	writeFrag := func(plain []byte) error {
		ct, err := chachaSeal(s.writeKey, chachaNonce(s.writeCounter), plain)
		if err != nil {
			return err
		}
		s.writeCounter++
		return s.c.writeFragment(charUUID, ct)
	}
	readFrag := func() ([]byte, error) {
		ct, err := s.c.readFragment(charUUID)
		if err != nil {
			return nil, err
		}
		pt, err := chachaOpen(s.readKey, chachaNonce(s.readCounter), ct)
		if err != nil {
			return nil, err
		}
		s.readCounter++
		return pt, nil
	}
	return exchange(opcode, s.c.nextTID(), iid, body, fragSize, writeFrag, readFrag)
}

// WriteCharacteristic writes a raw HAP value to a characteristic by UUID. The accessory
// intermittently rejects a write with a transient status (it has no "busy" code); the same
// write succeeds shortly after, so we retry a few times with a short backoff.
func (s *Session) WriteCharacteristic(charUUID bluetooth.UUID, value []byte) error {
	if prev, ok := s.lastWritten[charUUID]; ok && bytes.Equal(prev, value) {
		return nil // the accessory already holds this value
	}
	body := tlvs{}.add(hapParamValue, value).encode()
	var status byte
	for attempt := range writeRetries {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 40 * time.Millisecond)
		}
		var err error
		if status, _, err = s.request(charUUID, opCharWrite, body); err != nil {
			return err
		}
		switch status {
		case 0:
			s.lastWritten[charUUID] = append([]byte(nil), value...)
			return nil
		case statusMaxProcedures, statusInvalidReq:
			continue // transient; retry
		default:
			return fmt.Errorf("hap: write to %s returned status 0x%02x (%s)", charUUID, status, hapBLEStatusName(status))
		}
	}
	return fmt.Errorf("hap: write to %s still failing after %d attempts: status 0x%02x (%s)", charUUID, writeRetries, status, hapBLEStatusName(status))
}

// ReadCharacteristic reads a characteristic's current raw HAP value by UUID.
func (s *Session) ReadCharacteristic(charUUID bluetooth.UUID) ([]byte, error) {
	status, body, err := s.request(charUUID, opCharRead, nil)
	if err != nil {
		return nil, err
	}
	if status != 0 {
		return nil, fmt.Errorf("hap: read of %s returned status 0x%02x (%s)", charUUID, status, hapBLEStatusName(status))
	}
	return bleValue(body)
}

// SetOn turns the light on or off (HAP bool: one byte).
func (s *Session) SetOn(on bool) error {
	v := byte(0)
	if on {
		v = 1
	}
	return s.WriteCharacteristic(CharOn, []byte{v})
}

// SetBrightness sets brightness as a percentage 0–100 (HAP int: 32-bit little-endian).
func (s *Session) SetBrightness(percent int) error {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(int32(percent)))
	return s.WriteCharacteristic(CharBrightness, b[:])
}

// SetHue sets hue in degrees 0–360 (HAP float: 32-bit little-endian IEEE 754).
func (s *Session) SetHue(degrees float32) error {
	return s.WriteCharacteristic(CharHue, floatLE(degrees))
}

// SetSaturation sets saturation as a percentage 0–100 (HAP float).
func (s *Session) SetSaturation(percent float32) error {
	return s.WriteCharacteristic(CharSaturation, floatLE(percent))
}

func floatLE(f float32) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], math.Float32bits(f))
	return b[:]
}
