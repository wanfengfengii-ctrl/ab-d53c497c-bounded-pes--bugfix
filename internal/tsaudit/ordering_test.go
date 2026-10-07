package tsaudit_test

import (
	"testing"

	"mpegtsaudit/internal/tsaudit"
	"mpegtsaudit/internal/tsbuild"
)

// multiErrorStream is the archive scenario: packet 0 is a legal PAT, packet 1
// a legal PMT, packet 2 a legal PCR on the PMT-declared PCR PID, packet 3 is
// the first payload of media PID 0x0101 with a legal continuity counter but
// without PUSI, and packet 4 has had its sync byte destroyed.
func multiErrorStream() []byte {
	b := tsbuild.New()
	b.AddPAT()                       // 0
	b.AddPMT()                       // 1
	b.AddPCR(b.Opt.PCRPID, 0)        // 2: legal PCR
	b.AddPayload(b.Opt.Media[0].PID) // 3: first payload, PUSI clear
	b.AddRaw(make([]byte, 188))      // 4: sync byte 0x00
	return b.Bytes()
}

func TestBoundedPESReportsEarliestViolationBeforeBadSync(t *testing.T) {
	_, err := tsaudit.AuditPESBounded(multiErrorStream(), 1000, true)
	if err == nil {
		t.Fatal("stream must be rejected")
	}
	if err.Code != tsaudit.ErrPESMissingPUSI {
		t.Fatalf("code = %s, want %s", err.Code, tsaudit.ErrPESMissingPUSI)
	}
	if err.Packet != 3 {
		t.Errorf("packet = %d, want 3", err.Packet)
	}
	if err.PID != 0x0101 {
		t.Errorf("pid = %#x, want 0x0101", err.PID)
	}
}

func TestBoundedPESReportsEarliestViolationBeforeTransportError(t *testing.T) {
	// Same ordering requirement for every packet-header failure caught in
	// Pass A, not just a bad sync byte.
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	b.AddPCR(b.Opt.PCRPID, 0)
	b.AddPayload(b.Opt.Media[0].PID) // 3: first payload, PUSI clear
	b.AddPayload(b.Opt.Media[0].PID)
	b.MutateLast(func(buf []byte) { buf[1] |= 0x80 }) // 4: transport error indicator
	_, err := tsaudit.AuditPESBounded(b.Bytes(), 1000, true)
	if err == nil {
		t.Fatal("stream must be rejected")
	}
	if err.Code != tsaudit.ErrPESMissingPUSI || err.Packet != 3 || err.PID != 0x0101 {
		t.Fatalf("want %s at 3/0x0101, got %v", tsaudit.ErrPESMissingPUSI, err)
	}
}

func TestBoundedPESLegacyOrderingUnchangedWithoutParam(t *testing.T) {
	// With the bounded layer omitted the later header error stays the verdict,
	// exactly as before: TS_BAD_SYNC_BYTE at packet 4 carries no PID.
	_, err := tsaudit.Audit(multiErrorStream(), 1000)
	if err == nil {
		t.Fatal("stream must be rejected")
	}
	if err.Code != tsaudit.ErrBadSyncByte {
		t.Fatalf("code = %s, want %s", err.Code, tsaudit.ErrBadSyncByte)
	}
	if err.Packet != 4 {
		t.Fatalf("packet = %d, want 4", err.Packet)
	}
	if err.PID != -1 {
		t.Errorf("pid = %d, want -1 (absent from response)", err.PID)
	}
}

func TestBoundedPESSingleMissingPUSIControl(t *testing.T) {
	// Control stream containing only the bounded-PES violation.
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	b.AddPCR(b.Opt.PCRPID, 0)
	b.AddPayload(b.Opt.Media[0].PID) // 3
	b.AddPES(b.Opt.Media[1].PID, 0xC0, 100)
	_, err := tsaudit.AuditPESBounded(b.Bytes(), 1000, true)
	if err == nil || err.Code != tsaudit.ErrPESMissingPUSI || err.Packet != 3 || err.PID != 0x0101 {
		t.Fatalf("want %s at 3/0x0101, got %v", tsaudit.ErrPESMissingPUSI, err)
	}
}

func TestBoundedPESSingleBadSyncControl(t *testing.T) {
	// Control stream whose only located error is the bad sync byte. It also
	// proves a located header failure outranks the end-of-stream
	// TS_PES_NOT_FOUND condition on the silent media PID.
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	b.AddPCR(b.Opt.PCRPID, 0)
	b.AddPES(b.Opt.Media[0].PID, 0xE0, 100) // single-packet PES on PID 0x0101
	b.AddRaw(make([]byte, 188))             // 4: sync byte 0x00
	_, err := tsaudit.AuditPESBounded(b.Bytes(), 1000, true)
	if err == nil {
		t.Fatal("stream must be rejected")
	}
	if err.Code != tsaudit.ErrBadSyncByte || err.Packet != 4 || err.PID != -1 {
		t.Fatalf("want %s at 4/no-pid, got %v", tsaudit.ErrBadSyncByte, err)
	}
}

func TestBoundedPESEarliestLocatedErrorWinsWithinPassC(t *testing.T) {
	// A CC gap at packet 4 must still outrank a later missing-PUSI at
	// packet 5: the verdict is the earliest located violation overall.
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	b.AddPCR(b.Opt.PCRPID, 0)
	b.AddPES(b.Opt.Media[0].PID, 0xE0, 200) // packets 3-4: legal 2-packet PES
	b.MutateLast(func(buf []byte) {         // packet 4: break the continuity counter
		buf[3] = (buf[3] & 0xF0) | 5
	})
	b.AddPayload(b.Opt.Media[1].PID) // packet 5: first payload without PUSI
	_, err := tsaudit.AuditPESBounded(b.Bytes(), 1000, true)
	if err == nil {
		t.Fatal("stream must be rejected")
	}
	if err.Code != tsaudit.ErrCCGap || err.Packet != 4 || err.PID != 0x0101 {
		t.Fatalf("want %s at 4/0x0101, got %v", tsaudit.ErrCCGap, err)
	}
}
