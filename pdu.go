package hap

import "fmt"

// HAP-BLE PDU framing (HAP spec §7.3). A request addresses a characteristic by its
// instance ID (IID) and carries an opcode; the accessory replies with a status byte
// and an optional body. Logical PDUs larger than one GATT transmission are split into
// a first fragment carrying the full header and continuation fragments carrying just a
// control byte and the transaction ID.

// PDU opcodes (HAP spec Table 7-9). Only the ones we use are named.
const (
	opCharSignatureRead = 0x01
	opCharWrite         = 0x02
	opCharRead          = 0x03
	opSvcSignatureRead  = 0x06
)

const (
	controlRequest      = 0x00 // first fragment of a request
	controlContinuation = 0x80 // continuation fragment (bit 7 set)
)

// encodeRequest builds the logical request PDU. The body length field is present only
// when there is a body, matching how reads (no body) and writes (body) are framed.
func encodeRequest(opcode, tid byte, iid uint16, body []byte) []byte {
	buf := []byte{controlRequest, opcode, tid, byte(iid), byte(iid >> 8)}
	if len(body) > 0 {
		buf = append(buf, byte(len(body)), byte(len(body)>>8))
		buf = append(buf, body...)
	}
	return buf
}

// fragment splits a logical PDU into GATT-sized writes. The first fragment is sent
// verbatim (up to fragmentSize bytes); each continuation restates the control byte and
// transaction ID before its slice of the remaining bytes. The TID is passed explicitly
// because its offset differs between request and response PDUs.
func fragment(pdu []byte, tid byte, fragmentSize int) [][]byte {
	if fragmentSize < 3 {
		fragmentSize = 3
	}
	if len(pdu) <= fragmentSize {
		return [][]byte{append([]byte(nil), pdu...)}
	}
	out := [][]byte{append([]byte(nil), pdu[:fragmentSize]...)}
	for rest := pdu[fragmentSize:]; len(rest) > 0; {
		n := min(fragmentSize-2, len(rest))
		frag := append([]byte{controlContinuation, tid}, rest[:n]...)
		out = append(out, frag)
		rest = rest[n:]
	}
	return out
}

// parseFirstResponse decodes the first fragment of a response PDU. It returns the
// status byte, the total expected body length, and the portion of the body present in
// this fragment. The caller reads continuation fragments until it has bodyLen bytes.
func parseFirstResponse(tid byte, buf []byte) (status byte, bodyLen int, body []byte, err error) {
	if len(buf) < 3 {
		return 0, 0, nil, fmt.Errorf("hap: response fragment too short (%d bytes)", len(buf))
	}
	if buf[1] != tid {
		return 0, 0, nil, fmt.Errorf("hap: response transaction ID %d does not match request %d", buf[1], tid)
	}
	status = buf[2]
	if len(buf) < 5 {
		return status, 0, nil, nil // no body
	}
	bodyLen = int(buf[3]) | int(buf[4])<<8
	return status, bodyLen, append([]byte(nil), buf[5:]...), nil
}

// continuationBody strips the 2-byte continuation header (control + tid) from a fragment.
func continuationBody(buf []byte) ([]byte, error) {
	if len(buf) < 2 {
		return nil, fmt.Errorf("hap: continuation fragment too short (%d bytes)", len(buf))
	}
	return buf[2:], nil
}

// exchange runs one HAP transaction: it encodes and fragments the request, writes the
// fragments with writeFrag, then reads and reassembles the response with readFrag. The
// write/read functions move single fragments and let the session layer wrap them in
// encryption; fragSize bounds the plaintext fragment size.
func exchange(opcode, tid byte, iid uint16, body []byte, fragSize int,
	writeFrag func([]byte) error, readFrag func() ([]byte, error)) (status byte, respBody []byte, err error) {
	for _, frag := range fragment(encodeRequest(opcode, tid, iid, body), tid, fragSize) {
		if err := writeFrag(frag); err != nil {
			return 0, nil, fmt.Errorf("hap: writing request fragment: %w", err)
		}
	}
	first, err := readFrag()
	if err != nil {
		return 0, nil, fmt.Errorf("hap: reading response: %w", err)
	}
	status, bodyLen, respBody, err := parseFirstResponse(tid, first)
	if err != nil {
		return 0, nil, err
	}
	for len(respBody) < bodyLen {
		next, err := readFrag()
		if err != nil {
			return 0, nil, fmt.Errorf("hap: reading response continuation: %w", err)
		}
		more, err := continuationBody(next)
		if err != nil {
			return 0, nil, err
		}
		respBody = append(respBody, more...)
	}
	return status, respBody, nil
}
