package tsaudit_test

import (
	"testing"

	"mpegtsaudit/internal/tsaudit"
	"mpegtsaudit/internal/tsbuild"
)

// pesFragment builds a known-good bounded-PES stream: PAT, PMT, then three
// rounds of PCR + a multi-packet video PES + a single-packet audio PES.
func pesFragment() []byte {
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	for i := 0; i < 3; i++ {
		b.AddPCR(b.Opt.PCRPID, int64(i)*40*27000)
		b.AddPES(b.Opt.Media[0].PID, 0xE0, 400) // 406 bytes -> spans 3 TS packets
		b.AddPES(b.Opt.Media[1].PID, 0xC0, 100) // 106 bytes -> 1 TS packet
	}
	return b.Bytes()
}

func TestPESBoundedLegal(t *testing.T) {
	rep, err := tsaudit.AuditPESBounded(pesFragment(), 1000, true)
	if err != nil {
		t.Fatalf("bounded PES stream must pass: %v", err)
	}
	if len(rep.Media) != 2 {
		t.Fatalf("media entries = %d, want 2", len(rep.Media))
	}
	v, a := rep.Media[0], rep.Media[1]
	if v.PESCount == nil || *v.PESCount != 3 {
		t.Errorf("video pesCount = %v, want 3", v.PESCount)
	}
	if v.PESBytes == nil || *v.PESBytes != 3*406 {
		t.Errorf("video pesBytes = %v, want %d", v.PESBytes, 3*406)
	}
	if a.PESCount == nil || *a.PESCount != 3 {
		t.Errorf("audio pesCount = %v, want 3", a.PESCount)
	}
	if a.PESBytes == nil || *a.PESBytes != 3*106 {
		t.Errorf("audio pesBytes = %v, want %d", a.PESBytes, 3*106)
	}
}

func TestPESBoundedDisabledLeavesFramingUnchecked(t *testing.T) {
	// validFragment carries pattern payloads that are not PES at all; with the
	// layer disabled the audit must behave exactly like Audit.
	rep, err := tsaudit.AuditPESBounded(validFragment(), 1000, false)
	if err != nil {
		t.Fatalf("disabled PES layer must not reject: %v", err)
	}
	for _, m := range rep.Media {
		if m.PESCount != nil || m.PESBytes != nil {
			t.Errorf("pid %#x: PES fields must stay unset when disabled", m.PID)
		}
	}
}

func TestPESFirstPayloadMissingPUSI(t *testing.T) {
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	b.AddPCR(b.Opt.PCRPID, 0)
	b.AddPayload(b.Opt.Media[0].PID) // packet 3: payload without PUSI
	_, err := tsaudit.AuditPESBounded(b.Bytes(), 1000, true)
	if err == nil || err.Code != tsaudit.ErrPESMissingPUSI {
		t.Fatalf("want %s, got %v", tsaudit.ErrPESMissingPUSI, err)
	}
	if err.Packet != 3 || err.PID != b.Opt.Media[0].PID {
		t.Errorf("location = packet %d pid %#x, want 3 / %#x", err.Packet, err.PID, b.Opt.Media[0].PID)
	}
}

func TestPESRestartWithoutPUSI(t *testing.T) {
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	b.AddPCR(b.Opt.PCRPID, 0)
	b.AddPES(b.Opt.Media[0].PID, 0xE0, 178) // packet 3: 184 bytes, completes exactly
	b.AddPayload(b.Opt.Media[0].PID)        // packet 4: no PUSI after completion
	_, err := tsaudit.AuditPESBounded(b.Bytes(), 1000, true)
	if err == nil || err.Code != tsaudit.ErrPESMissingPUSI {
		t.Fatalf("want %s, got %v", tsaudit.ErrPESMissingPUSI, err)
	}
	if err.Packet != 4 {
		t.Errorf("packet = %d, want 4", err.Packet)
	}
}

func TestPESEarlyStart(t *testing.T) {
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	b.AddPCR(b.Opt.PCRPID, 0)
	hdr := tsbuild.PESBytes(0xE0, 1000) // declares 1006 bytes total
	b.AddPayloadChunk(b.Opt.Media[0].PID, true, hdr[:6])
	b.AddPES(b.Opt.Media[0].PID, 0xE0, 20) // packet 4: PUSI while 1000 bytes owed
	_, err := tsaudit.AuditPESBounded(b.Bytes(), 1000, true)
	if err == nil || err.Code != tsaudit.ErrPESEarlyStart {
		t.Fatalf("want %s, got %v", tsaudit.ErrPESEarlyStart, err)
	}
	if err.Packet != 4 || err.PID != b.Opt.Media[0].PID {
		t.Errorf("location = packet %d pid %#x", err.Packet, err.PID)
	}
}

func TestPESTrailingBytesOnStartPacket(t *testing.T) {
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	b.AddPCR(b.Opt.PCRPID, 0)
	pes := tsbuild.PESBytes(0xE0, 10) // declared total 16 bytes
	b.AddPayloadChunk(b.Opt.Media[0].PID, true, append(pes, make([]byte, 20)...))
	_, err := tsaudit.AuditPESBounded(b.Bytes(), 1000, true)
	if err == nil || err.Code != tsaudit.ErrPESTrailingBytes {
		t.Fatalf("want %s, got %v", tsaudit.ErrPESTrailingBytes, err)
	}
	if err.Packet != 3 {
		t.Errorf("packet = %d, want 3", err.Packet)
	}
}

func TestPESTrailingBytesOnContinuation(t *testing.T) {
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	b.AddPCR(b.Opt.PCRPID, 0)
	pes := tsbuild.PESBytes(0xE0, 200) // declared total 206 bytes
	b.AddPayloadChunk(b.Opt.Media[0].PID, true, pes[:184])
	// 22 bytes remain; the continuation carries 30.
	b.AddPayloadChunk(b.Opt.Media[0].PID, false, append(pes[184:], make([]byte, 8)...))
	_, err := tsaudit.AuditPESBounded(b.Bytes(), 1000, true)
	if err == nil || err.Code != tsaudit.ErrPESTrailingBytes {
		t.Fatalf("want %s, got %v", tsaudit.ErrPESTrailingBytes, err)
	}
	if err.Packet != 4 {
		t.Errorf("packet = %d, want 4", err.Packet)
	}
}

func TestPESBadPrefix(t *testing.T) {
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	b.AddPCR(b.Opt.PCRPID, 0)
	bad := []byte{0x00, 0x00, 0x02, 0xE0, 0x00, 0x10} // wrong start code prefix
	b.AddPayloadChunk(b.Opt.Media[0].PID, true, bad)
	_, err := tsaudit.AuditPESBounded(b.Bytes(), 1000, true)
	if err == nil || err.Code != tsaudit.ErrPESBadPrefix {
		t.Fatalf("want %s, got %v", tsaudit.ErrPESBadPrefix, err)
	}
}

func TestPESZeroLength(t *testing.T) {
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	b.AddPCR(b.Opt.PCRPID, 0)
	z := []byte{0x00, 0x00, 0x01, 0xE0, 0x00, 0x00} // PES_packet_length = 0
	b.AddPayloadChunk(b.Opt.Media[0].PID, true, z)
	_, err := tsaudit.AuditPESBounded(b.Bytes(), 1000, true)
	if err == nil || err.Code != tsaudit.ErrPESZeroLength {
		t.Fatalf("want %s, got %v", tsaudit.ErrPESZeroLength, err)
	}
}

func TestPESHeaderShort(t *testing.T) {
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	b.AddPCR(b.Opt.PCRPID, 0)
	b.AddPayloadChunk(b.Opt.Media[0].PID, true, []byte{0x00, 0x00, 0x01, 0xE0, 0x00})
	_, err := tsaudit.AuditPESBounded(b.Bytes(), 1000, true)
	if err == nil || err.Code != tsaudit.ErrPESHeaderShort {
		t.Fatalf("want %s, got %v", tsaudit.ErrPESHeaderShort, err)
	}
}

func TestPESTruncatedAtEnd(t *testing.T) {
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	b.AddPCR(b.Opt.PCRPID, 0)
	hdr := tsbuild.PESBytes(0xE0, 1000) // declares 1006 bytes, only 6 delivered
	b.AddPayloadChunk(b.Opt.Media[0].PID, true, hdr[:6])
	b.AddPES(b.Opt.Media[1].PID, 0xC0, 100) // audio PID stays complete
	_, err := tsaudit.AuditPESBounded(b.Bytes(), 1000, true)
	if err == nil || err.Code != tsaudit.ErrPESTruncated {
		t.Fatalf("want %s, got %v", tsaudit.ErrPESTruncated, err)
	}
	if err.Packet != 3 || err.PID != b.Opt.Media[0].PID {
		t.Errorf("location = packet %d pid %#x, want 3 / %#x",
			err.Packet, err.PID, b.Opt.Media[0].PID)
	}
}

func TestPESNotFoundOnSilentMediaPID(t *testing.T) {
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	b.AddPCR(b.Opt.PCRPID, 0)
	b.AddPES(b.Opt.Media[0].PID, 0xE0, 100) // only the video PID carries PES
	_, err := tsaudit.AuditPESBounded(b.Bytes(), 1000, true)
	if err == nil || err.Code != tsaudit.ErrPESNotFound {
		t.Fatalf("want %s, got %v", tsaudit.ErrPESNotFound, err)
	}
	if err.PID != b.Opt.Media[1].PID {
		t.Errorf("pid = %#x, want %#x", err.PID, b.Opt.Media[1].PID)
	}
}

func TestPESSpanningManyPackets(t *testing.T) {
	// A large PES exercises accumulation across many continuation packets.
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	b.AddPCR(b.Opt.PCRPID, 0)
	b.AddPES(b.Opt.Media[0].PID, 0xE0, 0xFFFF) // 65541 bytes -> 357 packets
	b.AddPES(b.Opt.Media[1].PID, 0xC0, 50)
	rep, err := tsaudit.AuditPESBounded(b.Bytes(), 1000, true)
	if err != nil {
		t.Fatalf("large PES must pass: %v", err)
	}
	if got := *rep.Media[0].PESBytes; got != 6+0xFFFF {
		t.Errorf("pesBytes = %d, want %d", got, 6+0xFFFF)
	}
}

// multiErrorBoundedFragment reproduces the archival scenario: packet 3 is the
// media PID's first payload with a legal continuity counter but PUSI clear
// (bounded-PES violation), and packet 4 has a corrupt sync byte.
func multiErrorBoundedFragment() []byte {
	b := tsbuild.New()
	b.AddPAT()                                       // 0
	b.AddPMT()                                       // 1
	b.AddPCR(b.Opt.PCRPID, 0)                        // 2
	b.AddPayload(b.Opt.Media[0].PID)                 // 3: PUSI clear, CC legal
	b.AddPayload(b.Opt.Media[0].PID)                 // 4: CC legal ...
	b.MutateLast(func(buf []byte) { buf[0] = 0x00 }) //    ... but sync byte 0x00
	return b.Bytes()
}

func TestPESBoundedEarlierViolationBeatsLaterBadSync(t *testing.T) {
	_, err := tsaudit.AuditPESBounded(multiErrorBoundedFragment(), 1000, true)
	if err == nil {
		t.Fatal("stream must be rejected")
	}
	if err.Code != tsaudit.ErrPESMissingPUSI {
		t.Fatalf("code = %s, want %s (later bad sync must not mask it)", err.Code, tsaudit.ErrPESMissingPUSI)
	}
	if err.Packet != 3 {
		t.Errorf("packet = %d, want 3", err.Packet)
	}
	if err.PID != 0x0101 {
		t.Errorf("pid = %#x, want 0x0101", err.PID)
	}
}

func TestPESBoundedSingleMissingPUSIControl(t *testing.T) {
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	b.AddPCR(b.Opt.PCRPID, 0)
	b.AddPayload(b.Opt.Media[0].PID) // packet 3 alone violates bounded PES
	_, err := tsaudit.AuditPESBounded(b.Bytes(), 1000, true)
	if err == nil || err.Code != tsaudit.ErrPESMissingPUSI {
		t.Fatalf("want %s, got %v", tsaudit.ErrPESMissingPUSI, err)
	}
	if err.Packet != 3 || err.PID != 0x0101 {
		t.Errorf("location = packet %d pid %#x, want 3 / 0x0101", err.Packet, err.PID)
	}
}

func TestPESBoundedSingleBadSyncControl(t *testing.T) {
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	b.AddPCR(b.Opt.PCRPID, 0)
	b.AddPayload(b.Opt.Media[0].PID) // packet 3 ...
	b.MutateLast(func(buf []byte) { buf[0] = 0x00 })
	_, err := tsaudit.AuditPESBounded(b.Bytes(), 1000, true)
	if err == nil || err.Code != tsaudit.ErrBadSyncByte {
		t.Fatalf("want %s, got %v", tsaudit.ErrBadSyncByte, err)
	}
	if err.Packet != 3 {
		t.Errorf("packet = %d, want 3", err.Packet)
	}
	if err.PID != -1 {
		t.Errorf("pid = %d, want -1 (no PID for a bad sync byte)", err.PID)
	}
}

func TestPESBoundedDisabledKeepsHeaderErrorFirst(t *testing.T) {
	// Without pes=bounded the PES layer is absent: the later packet-header
	// corruption remains the reported error, exactly as before.
	_, err := tsaudit.AuditPESBounded(multiErrorBoundedFragment(), 1000, false)
	if err == nil || err.Code != tsaudit.ErrBadSyncByte {
		t.Fatalf("want %s, got %v", tsaudit.ErrBadSyncByte, err)
	}
	if err.Packet != 4 {
		t.Errorf("packet = %d, want 4", err.Packet)
	}
	if err.PID != -1 {
		t.Errorf("pid = %d, want -1", err.PID)
	}
}
