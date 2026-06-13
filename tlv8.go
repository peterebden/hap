package hap

import "fmt"

// TLV8 is HomeKit's type-length-value encoding, used to carry the pair-setup and
// pair-verify messages (HAP spec §14.1). Each item is a one-byte type, a one-byte
// length, then that many value bytes. A value longer than 255 bytes is split into
// consecutive items of the same type, which a reader concatenates back together;
// two distinct values of the same type are therefore separated by a zero-length
// item of a different type (the separator).

// TLV item types used during pairing (HAP spec Table 5-6).
const (
	tlvMethod        = 0x00
	tlvIdentifier    = 0x01
	tlvSalt          = 0x02
	tlvPublicKey     = 0x03
	tlvProof         = 0x04
	tlvEncryptedData = 0x05
	tlvState         = 0x06
	tlvError         = 0x07
	tlvRetryDelay    = 0x08
	tlvSignature     = 0x0a
	tlvPermissions   = 0x0b
	tlvFlags         = 0x13
	tlvSeparator     = 0xff
)

// tlv is a single decoded item; values >255 bytes are already reassembled.
type tlv struct {
	Type  byte
	Value []byte
}

// tlvs is an ordered list of items. Order matters and duplicate types are legal,
// so this is a slice rather than a map.
type tlvs []tlv

// add appends an item. A nil/empty value encodes as a zero-length item.
func (t tlvs) add(typ byte, value []byte) tlvs {
	return append(t, tlv{Type: typ, Value: value})
}

// addByte appends a single-byte item, the common case for State/Method/Error.
func (t tlvs) addByte(typ, value byte) tlvs {
	return append(t, tlv{Type: typ, Value: []byte{value}})
}

// encode serialises the items, fragmenting any value longer than 255 bytes into
// consecutive same-type chunks.
func (t tlvs) encode() []byte {
	var out []byte
	for _, item := range t {
		v := item.Value
		// A zero-length value still emits one item.
		for {
			n := min(len(v), 255)
			out = append(out, item.Type, byte(n))
			out = append(out, v[:n]...)
			v = v[n:]
			if len(v) == 0 {
				break
			}
		}
	}
	return out
}

// decodeTLV parses a TLV8 buffer, concatenating consecutive items that share a type
// (the reassembly rule for values that were fragmented at 255 bytes).
func decodeTLV(buf []byte) (tlvs, error) {
	var out tlvs
	for i := 0; i < len(buf); {
		if i+2 > len(buf) {
			return nil, fmt.Errorf("hap: truncated TLV header at offset %d", i)
		}
		typ := buf[i]
		length := int(buf[i+1])
		i += 2
		if i+length > len(buf) {
			return nil, fmt.Errorf("hap: TLV item of length %d overruns buffer at offset %d", length, i)
		}
		value := buf[i : i+length]
		i += length
		// Merge with the previous item if the type repeats and was a full 255-byte
		// fragment (i.e. a continuation), per the concatenation rule.
		if n := len(out); n > 0 && out[n-1].Type == typ {
			out[n-1].Value = append(out[n-1].Value, value...)
		} else {
			out = append(out, tlv{Type: typ, Value: append([]byte(nil), value...)})
		}
	}
	return out, nil
}

// first returns the value of the first item with the given type, and whether it was found.
func (t tlvs) first(typ byte) ([]byte, bool) {
	for _, item := range t {
		if item.Type == typ {
			return item.Value, true
		}
	}
	return nil, false
}

// firstByte returns the first byte of the first item of the given type, or (0, false).
func (t tlvs) firstByte(typ byte) (byte, bool) {
	if v, ok := t.first(typ); ok && len(v) > 0 {
		return v[0], true
	}
	return 0, false
}
