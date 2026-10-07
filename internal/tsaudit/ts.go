package tsaudit

const (
	packetSize   = 188
	syncByte     = 0x47
	pidPAT       = 0x0000
	flagTEI      = 0x80 // transport error indicator
	flagPUSI     = 0x40 // payload unit start indicator
	flagPriority = 0x20
	maskScramble = 0xC0 // adaptation_field_control upper bits, != 00 => scrambled
	maskAFC      = 0x30
	afcReserved  = 0x00
	afcPayload   = 0x10
	afcAdapt     = 0x20
	afcBoth      = 0x30
	maskCC       = 0x0F

	afFlagDiscontinuity = 0x80
	afFlagRandomAccess  = 0x40
	afFlagESPriority    = 0x20
	afFlagPCR           = 0x10
	afFlagOPCR          = 0x08
	afFlagSplicing      = 0x04
	afFlagTransport     = 0x02
	afFlagAdaptExt      = 0x01

	stuffingByte = 0xFF
)

// Packet is a parsed view of one MPEG-TS 188-byte packet.
type Packet struct {
	PUSI            bool
	TEI             bool
	PID             int
	Scrambled       bool
	AFC             int
	CC              int
	Adaptation      []byte // adaptation field bytes after the length byte (nil if none)
	PayloadStart    int    // offset of payload within the packet (== len when none)
	HasAdaptation   bool
	HasPayload      bool
	AdaptLengthByte int // offset of adaptation_field_length byte, -1 when absent
}

// parsePacket performs the header-level checks shared by every packet and
// returns the parsed packet or an AuditError.
func parsePacket(raw []byte, idx int) (*Packet, *AuditError) {
	if raw[0] != syncByte {
		return nil, auditError(ErrBadSyncByte, "sync byte is not 0x47", idx, -1)
	}
	if raw[1]&flagTEI != 0 {
		pid := int(raw[1]&0x1F)<<8 | int(raw[2])
		return nil, auditError(ErrTransportError, "transport error indicator set", idx, pid)
	}

	p := &Packet{
		PUSI:            raw[1]&flagPUSI != 0,
		TEI:             raw[1]&flagTEI != 0,
		PID:             int(raw[1]&0x1F)<<8 | int(raw[2]),
		Scrambled:       raw[3]&maskScramble != 0,
		AFC:             int(raw[3] & maskAFC),
		CC:              int(raw[3] & maskCC),
		AdaptLengthByte: -1,
		PayloadStart:    packetSize,
	}

	if p.Scrambled {
		return nil, auditError(ErrScrambled, "transport scrambling control is not 00", idx, p.PID)
	}
	if p.AFC == afcReserved {
		return nil, auditError(ErrSectionSyntax, "adaptation_field_control value 00 is reserved", idx, p.PID)
	}

	off := 4
	p.HasAdaptation = p.AFC == afcAdapt || p.AFC == afcBoth
	p.HasPayload = p.AFC == afcPayload || p.AFC == afcBoth

	if p.HasAdaptation {
		p.AdaptLengthByte = off
		adLen := int(raw[off])
		off++
		if adLen > packetSize-off {
			return nil, auditError(ErrSectionSyntax, "adaptation field length exceeds packet", idx, p.PID)
		}
		if adLen > 0 {
			p.Adaptation = raw[off : off+adLen : off+adLen]
		}
		off += adLen
	}
	if p.HasPayload {
		p.PayloadStart = off
	}
	return p, nil
}

// adaptationFlags returns the adaptation_field flags byte (0 when absent).
func (p *Packet) adaptationFlags() byte {
	if len(p.Adaptation) >= 1 {
		return p.Adaptation[0]
	}
	return 0
}

// pcr extracts a 42-bit PCR (base*300 + extension) from the adaptation field.
// Returns (value, true) when a PCR flag and a complete PCR field are present.
// A present PCR flag without enough bytes is reported as malformed input.
func (p *Packet) pcr() (int64, bool, bool) {
	if p.adaptationFlags()&afFlagPCR == 0 {
		return 0, false, false
	}
	if len(p.Adaptation) < 7 {
		return 0, true, false
	}
	b := p.Adaptation[1:7]
	base := int64(b[0])<<25 | int64(b[1])<<17 | int64(b[2])<<9 |
		int64(b[3])<<1 | int64(b[4]>>7)
	ext := int64(b[4]&0x01)<<8 | int64(b[5])
	return base*300 + ext, true, true
}
