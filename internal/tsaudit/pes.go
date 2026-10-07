package tsaudit

// pesHeaderLen is the fixed PES header prefix: 3-byte start code, stream_id
// and the 2-byte PES_packet_length field.
const pesHeaderLen = 6

// pesState tracks bounded-PES framing for one PMT media PID. Every payload
// byte must belong to exactly one bounded PES (00 00 01 prefix, stream_id,
// non-zero PES_packet_length) and each PES must end exactly at a payload
// boundary, so the declared length is accumulated across TS packets.
type pesState struct {
	remaining int64 // bytes still owed to complete the open PES (0 = none open)
	declared  int64 // total length of the open PES, header included
	startPkt  int   // packet where the open PES began
	count     int64 // complete PES packets
	bytes     int64 // summed declared length of complete PES packets
}

// consume folds one TS payload of the media PID into the framing state.
// pkt is the 0-based packet index used for error reporting.
func (st *pesState) consume(payload []byte, pusi bool, pkt, pid int) *AuditError {
	if len(payload) == 0 && !pusi {
		return nil // no PES bytes carried, nothing to frame
	}
	if pusi {
		if st.remaining > 0 {
			return auditError(ErrPESEarlyStart, "PUSI arrived before the previous PES completed", pkt, pid)
		}
		if len(payload) < pesHeaderLen {
			return auditError(ErrPESHeaderShort, "PES start packet is shorter than the 6-byte PES header", pkt, pid)
		}
		if payload[0] != 0x00 || payload[1] != 0x00 || payload[2] != 0x01 {
			return auditError(ErrPESBadPrefix, "PES payload does not start with the 00 00 01 prefix", pkt, pid)
		}
		plen := int64(payload[4])<<8 | int64(payload[5])
		if plen == 0 {
			return auditError(ErrPESZeroLength, "PES_packet_length is zero; only bounded PES are accepted", pkt, pid)
		}
		st.declared = pesHeaderLen + plen
		st.startPkt = pkt
		st.remaining = st.declared
	} else if st.remaining == 0 {
		return auditError(ErrPESMissingPUSI, "payload arrived with no PES open and PUSI clear", pkt, pid)
	}

	take := int64(len(payload))
	if take > st.remaining {
		return auditError(ErrPESTrailingBytes, "PES completes before the packet payload ends; trailing bytes present", pkt, pid)
	}
	st.remaining -= take
	if st.remaining == 0 {
		st.count++
		st.bytes += st.declared
		st.declared = 0
	}
	return nil
}

// finish reports end-of-stream violations: an incomplete PES still owes
// bytes (located at the packet where that PES started), or the PID never
// carried a single complete PES.
func (st *pesState) finish(pid int) *AuditError {
	if st.remaining > 0 {
		return auditError(ErrPESTruncated, "stream ends before the declared PES length is delivered", st.startPkt, pid)
	}
	if st.count == 0 {
		return auditError(ErrPESNotFound, "PMT media PID carried no PES", 0, pid)
	}
	return nil
}
