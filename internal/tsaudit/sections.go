package tsaudit

// tableSection is a PAT/PMT section that arrived complete in one packet.
type tableSection struct {
	packet  int
	raw     []byte // whole section, table_id through CRC_32
	version int

	// PAT fields
	programs []patProgram

	// PMT fields
	pcrPID    int
	mediaPIDs []int
}

type patProgram struct {
	number int
	pid    int
}

// parseTablePacket extracts and validates the single PSI section that must be
// carried complete in packet p. expectTableID selects PAT (0x00) or PMT
// (0x02); the supplied error codes identify which table failed.
func parseTablePacket(raw []byte, p *Packet, idx int, expectTableID byte,
	tableIDCode, spanCode, truncCode string) (*tableSection, *AuditError) {

	if !p.HasPayload || p.PayloadStart >= packetSize {
		return nil, auditError(ErrSectionSyntax, "section start packet carries no payload", idx, p.PID)
	}
	payload := raw[p.PayloadStart:]
	if len(payload) < 1 {
		return nil, auditError(truncCode, "missing pointer_field", idx, p.PID)
	}

	pointer := int(payload[0])
	if 1+pointer+3 > len(payload) {
		return nil, auditError(truncCode, "pointer_field reaches past packet", idx, p.PID)
	}
	// Bytes between the pointer field and the section start must be stuffing.
	for i := 1; i < 1+pointer; i++ {
		if payload[i] != stuffingByte {
			return nil, auditError(ErrSectionPointer, "non-0xFF byte in pointer filler area", idx, p.PID)
		}
	}

	start := 1 + pointer
	tableID := payload[start]
	if tableID != expectTableID {
		return nil, auditError(tableIDCode, "unexpected table_id", idx, p.PID)
	}
	if payload[start+1]&0x80 == 0 {
		return nil, auditError(ErrSectionSyntax, "section_syntax_indicator is not 1", idx, p.PID)
	}
	sectionLen := int(payload[start+1]&0x0F)<<8 | int(payload[start+2])
	if sectionLen < 9 || sectionLen > 1021 {
		return nil, auditError(ErrBadSectionLength, "section_length out of range", idx, p.PID)
	}
	end := start + 3 + sectionLen
	if end > len(payload) {
		return nil, auditError(spanCode, "section continues beyond a single packet", idx, p.PID)
	}
	// Anything after the complete section in this packet must be stuffing.
	for i := end; i < len(payload); i++ {
		if payload[i] != stuffingByte {
			return nil, auditError(ErrSectionSyntax, "non-0xFF trailing byte after section", idx, p.PID)
		}
	}

	sec := payload[start:end]
	if CRC32MPEG(sec) != 0 {
		return nil, auditError(ErrSectionCRC, "section CRC_32 mismatch", idx, p.PID)
	}

	s := &tableSection{
		packet:  idx,
		raw:     append([]byte(nil), sec...),
		version: int(sec[5]>>1) & 0x1F,
		pcrPID:  -1,
	}

	switch expectTableID {
	case 0x00:
		if err := parsePATBody(s); err != nil {
			err.Packet = idx
			err.PID = p.PID
			return nil, err
		}
	case 0x02:
		if err := parsePMTBody(s); err != nil {
			err.Packet = idx
			err.PID = p.PID
			return nil, err
		}
	}
	return s, nil
}

func parsePATBody(s *tableSection) *AuditError {
	loopEnd := len(s.raw) - 4 // CRC occupies the final 4 bytes
	i := 8
	for i+4 <= loopEnd {
		number := int(s.raw[i])<<8 | int(s.raw[i+1])
		pid := int(s.raw[i+2]&0x1F)<<8 | int(s.raw[i+3])
		if number != 0 { // program_number 0 carries the network_PID, not a program
			s.programs = append(s.programs, patProgram{number, pid})
		}
		i += 4
	}
	if i != loopEnd {
		return auditError(ErrSectionSyntax, "PAT program loop is not integral", s.packet, pidPAT)
	}
	return nil
}

func parsePMTBody(s *tableSection) *AuditError {
	if len(s.raw) < 16 {
		return auditError(ErrSectionTruncated, "PMT section too short", s.packet, -1)
	}
	s.pcrPID = int(s.raw[8]&0x1F)<<8 | int(s.raw[9])
	infoLen := int(s.raw[10]&0x0F)<<8 | int(s.raw[11])
	loopEnd := len(s.raw) - 4
	i := 12 + infoLen
	if i > loopEnd {
		return auditError(ErrSectionSyntax, "program_info_length exceeds section", s.packet, -1)
	}
	for i+5 <= loopEnd {
		pid := int(s.raw[i+1]&0x1F)<<8 | int(s.raw[i+2])
		esiLen := int(s.raw[i+3]&0x0F)<<8 | int(s.raw[i+4])
		i += 5
		if i+esiLen > loopEnd {
			return auditError(ErrSectionSyntax, "ES_info_length exceeds section", s.packet, pid)
		}
		s.mediaPIDs = append(s.mediaPIDs, pid)
		i += esiLen
	}
	if i != loopEnd {
		return auditError(ErrSectionSyntax, "PMT elementary stream loop is not integral", s.packet, -1)
	}
	return nil
}
