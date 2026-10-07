package tsaudit_test

import (
	"testing"

	"mpegtsaudit/internal/tsaudit"
	"mpegtsaudit/internal/tsbuild"
)

// validFragment builds a known-good stream: PAT, PMT, then interleaved PCR and
// media packets with 40 ms PCR spacing.
func validFragment() []byte {
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	const step = 40 * 27000 // 40 ms in 27 MHz units
	for i := 0; i < 5; i++ {
		pcr := int64(i) * step
		b.AddPCR(b.Opt.PCRPID, pcr)
		b.AddPayload(b.Opt.Media[0].PID)
		b.AddPayload(b.Opt.Media[1].PID)
	}
	return b.Bytes()
}

func TestValidFragment(t *testing.T) {
	rep, err := tsaudit.Audit(validFragment(), 1000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rep.ProgramNumber != 1 {
		t.Errorf("program number = %d, want 1", rep.ProgramNumber)
	}
	if rep.PCRPID != 0x0100 || len(rep.MediaPIDs) != 2 {
		t.Errorf("signalling wrong: pcrPID=%#x media=%v", rep.PCRPID, rep.MediaPIDs)
	}
	if rep.PacketCount != 17 {
		t.Errorf("packet count = %d, want 17", rep.PacketCount)
	}
	if rep.FirstPCR == nil || rep.FirstPCR.Value27MHz != 0 {
		t.Errorf("first PCR wrong: %+v", rep.FirstPCR)
	}
	if rep.LastPCR == nil || rep.LastPCR.Value27MHz != 160*27000 {
		t.Errorf("last PCR wrong: %+v", rep.LastPCR)
	}
	if rep.DurationMs != 160 {
		t.Errorf("duration = %v ms, want 160", rep.DurationMs)
	}
	// 10 media packets * 184 payload bytes
	if rep.PayloadBytes != 10*184 {
		t.Errorf("payload bytes = %d, want %d", rep.PayloadBytes, 10*184)
	}
}

func TestRepeatedPATPMTSameVersion(t *testing.T) {
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	b.AddPAT()
	b.AddPMT()
	b.AddPCR(b.Opt.PCRPID, 0)
	b.AddPayload(b.Opt.Media[0].PID)
	b.AddPayload(b.Opt.Media[1].PID)
	b.AddPCR(b.Opt.PCRPID, 40*27000)
	if _, err := tsaudit.Audit(b.Bytes(), 1000); err != nil {
		t.Fatalf("identical repeated PAT/PMT must pass: %v", err)
	}
}

func TestPATVersionMismatch(t *testing.T) {
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	b.Opt.Version = 1
	b.AddPAT() // same structure, different version
	b.AddPCR(b.Opt.PCRPID, 0)
	b.AddPayload(b.Opt.Media[0].PID)
	_, err := tsaudit.Audit(b.Bytes(), 1000)
	if err == nil || err.Code != tsaudit.ErrPATVersionMismatch {
		t.Fatalf("want %s, got %v", tsaudit.ErrPATVersionMismatch, err)
	}
}

func TestMultiProgramRejected(t *testing.T) {
	b := tsbuild.New()
	b.AddPATWith(b.MultiPATSection(map[int]int{1: 0x1000, 2: 0x1001}))
	_, err := tsaudit.Audit(b.Bytes(), 1000)
	if err == nil || err.Code != tsaudit.ErrMultiProgram {
		t.Fatalf("want %s, got %v", tsaudit.ErrMultiProgram, err)
	}
}

func TestTransportErrorRejected(t *testing.T) {
	b := tsbuild.New()
	b.AddPAT()
	b.MutateLast(func(buf []byte) { buf[1] |= 0x80 })
	_, err := tsaudit.Audit(b.Bytes(), 1000)
	if err == nil || err.Code != tsaudit.ErrTransportError {
		t.Fatalf("want %s, got %v", tsaudit.ErrTransportError, err)
	}
}

func TestScramblingRejected(t *testing.T) {
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	b.AddPayload(b.Opt.Media[0].PID)
	b.MutateLast(func(buf []byte) { buf[3] |= 0x80 })
	_, err := tsaudit.Audit(b.Bytes(), 1000)
	if err == nil || err.Code != tsaudit.ErrScrambled {
		t.Fatalf("want %s, got %v", tsaudit.ErrScrambled, err)
	}
}

func TestDiscontinuityRejected(t *testing.T) {
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	b.AddPCR(b.Opt.PCRPID, 0).
		MutateLast(func(buf []byte) { buf[5] |= 0x80 }) // adaptation flags
	_, err := tsaudit.Audit(b.Bytes(), 1000)
	if err == nil || err.Code != tsaudit.ErrDiscontinuity {
		t.Fatalf("want %s, got %v", tsaudit.ErrDiscontinuity, err)
	}
}

func TestBadSyncByte(t *testing.T) {
	d := validFragment()
	d[0] = 0x00
	_, err := tsaudit.Audit(d, 1000)
	if err == nil || err.Code != tsaudit.ErrBadSyncByte {
		t.Fatalf("want %s, got %v", tsaudit.ErrBadSyncByte, err)
	}
}

func TestNotPacketAligned(t *testing.T) {
	_, err := tsaudit.Audit(make([]byte, 189), 1000)
	if err == nil || err.Code != tsaudit.ErrNotPacketAligned {
		t.Fatalf("want %s, got %v", tsaudit.ErrNotPacketAligned, err)
	}
}

func TestEmptyBody(t *testing.T) {
	_, err := tsaudit.Audit(nil, 1000)
	if err == nil || err.Code != tsaudit.ErrEmptyBody {
		t.Fatalf("want %s, got %v", tsaudit.ErrEmptyBody, err)
	}
}

func TestSectionCRCMismatch(t *testing.T) {
	b := tsbuild.New()
	b.AddPAT()
	b.MutateLast(func(buf []byte) {
		buf[10] ^= 0xFF // corrupt TS id byte inside section; CRC must catch it
	})
	_, err := tsaudit.Audit(b.Bytes(), 1000)
	if err == nil || err.Code != tsaudit.ErrSectionCRC {
		t.Fatalf("want %s, got %v", tsaudit.ErrSectionCRC, err)
	}
}

func TestSectionSpansPacket(t *testing.T) {
	// PAT packet without PUSI looks like a continuation of another packet.
	b := tsbuild.New()
	b.AddPAT()
	b.MutateLast(func(buf []byte) { buf[1] &^= 0x40 })
	_, err := tsaudit.Audit(b.Bytes(), 1000)
	if err == nil || err.Code != tsaudit.ErrPATSectionSpansPacket {
		t.Fatalf("want %s, got %v", tsaudit.ErrPATSectionSpansPacket, err)
	}
}

func TestCCGapOnPayload(t *testing.T) {
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	pid := b.Opt.Media[0].PID
	b.AddPayload(pid)
	b.AddPayload(pid)
	b.MutateLast(func(buf []byte) { buf[3] = (buf[3] & 0xF0) | 5 }) // jump CC
	_, err := tsaudit.Audit(b.Bytes(), 1000)
	if err == nil || err.Code != tsaudit.ErrCCGap {
		t.Fatalf("want %s, got %v", tsaudit.ErrCCGap, err)
	}
}

func TestCCDuplicatePayload(t *testing.T) {
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	pid := b.Opt.Media[0].PID
	b.AddPayload(pid)
	// Replay identical packet (same CC, has payload).
	last := b.Bytes()[len(b.Bytes())-188:]
	b.AddRaw(append([]byte(nil), last...))
	_, err := tsaudit.Audit(b.Bytes(), 1000)
	if err == nil || err.Code != tsaudit.ErrCCDuplicatePayload {
		t.Fatalf("want %s, got %v", tsaudit.ErrCCDuplicatePayload, err)
	}
}

func TestAdaptationOnlyKeepsCC(t *testing.T) {
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	b.AddPCR(b.Opt.PCRPID, 0)
	b.AddAdaptationOnly(b.Opt.PCRPID) // CC unchanged -> legal
	b.AddPCR(b.Opt.PCRPID, 40*27000)
	if _, err := tsaudit.Audit(b.Bytes(), 1000); err != nil {
		t.Fatalf("adaptation-only with unchanged CC must pass: %v", err)
	}
}

func TestAdaptationOnlyChangedCCRejected(t *testing.T) {
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	b.AddPCR(b.Opt.PCRPID, 0)
	b.AddAdaptationOnly(b.Opt.PCRPID)
	b.MutateLast(func(buf []byte) { buf[3]++ }) // CC advanced on adapt-only
	_, err := tsaudit.Audit(b.Bytes(), 1000)
	if err == nil || err.Code != tsaudit.ErrCCGap {
		t.Fatalf("want %s, got %v", tsaudit.ErrCCGap, err)
	}
}

func TestCCWrapsModulo16(t *testing.T) {
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	pid := b.Opt.Media[0].PID
	b.AddPCR(b.Opt.PCRPID, 0)
	// 17 payload packets take CC 0..15 and then wrap back to 0.
	for i := 0; i < 17; i++ {
		b.AddPayload(pid)
	}
	b.AddPCR(b.Opt.PCRPID, 40*27000)
	if _, err := tsaudit.Audit(b.Bytes(), 1000); err != nil {
		t.Fatalf("CC must wrap 15->0: %v", err)
	}
}

func TestPCRGapAtLimitAccepted(t *testing.T) {
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	b.AddPCR(b.Opt.PCRPID, 0)
	b.AddPayload(b.Opt.Media[0].PID)
	b.AddPCR(b.Opt.PCRPID, 1000*27000) // exactly maxPcrGapMs
	if _, err := tsaudit.Audit(b.Bytes(), 1000); err != nil {
		t.Fatalf("gap equal to the limit must pass: %v", err)
	}
}

func TestPCROnWrongPID(t *testing.T) {
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	b.AddPCR(b.Opt.Media[0].PID, 0) // PCR on a media PID
	_, err := tsaudit.Audit(b.Bytes(), 1000)
	if err == nil || err.Code != tsaudit.ErrPCROnWrongPID {
		t.Fatalf("want %s, got %v", tsaudit.ErrPCROnWrongPID, err)
	}
}

func TestPCRReversed(t *testing.T) {
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	b.AddPCR(b.Opt.PCRPID, 100*27000)
	b.AddPayload(b.Opt.Media[0].PID)
	b.AddPCR(b.Opt.PCRPID, 90*27000) // backwards, small delta
	_, err := tsaudit.Audit(b.Bytes(), 1000)
	if err == nil || err.Code != tsaudit.ErrPCRReversed {
		t.Fatalf("want %s, got %v", tsaudit.ErrPCRReversed, err)
	}
}

func TestPCRGapExceeded(t *testing.T) {
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	b.AddPCR(b.Opt.PCRPID, 0)
	b.AddPayload(b.Opt.Media[0].PID)
	b.AddPCR(b.Opt.PCRPID, 1500*27000) // > 1000 ms cap param
	_, err := tsaudit.Audit(b.Bytes(), 1000)
	if err == nil || err.Code != tsaudit.ErrPCRGapExceeded {
		t.Fatalf("want %s, got %v", tsaudit.ErrPCRGapExceeded, err)
	}
}

func TestPCRAcrossWrap(t *testing.T) {
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	const cycle = int64(1) << 33 * 300
	high := cycle - 30*27000 // 30 ms before wrap
	b.AddPCR(b.Opt.PCRPID, high)
	b.AddPayload(b.Opt.Media[0].PID)
	b.AddPCR(b.Opt.PCRPID, 10*27000) // 40 ms later after wraparound
	rep, err := tsaudit.Audit(b.Bytes(), 1000)
	if err != nil {
		t.Fatalf("wraparound PCR must pass: %v", err)
	}
	if rep.DurationMs != 40 {
		t.Errorf("duration across wrap = %v, want 40", rep.DurationMs)
	}
}

func TestUnknownPIDRejected(t *testing.T) {
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	b.AddPayload(0x0200) // not in PMT
	_, err := tsaudit.Audit(b.Bytes(), 1000)
	if err == nil || err.Code != tsaudit.ErrUnknownPID {
		t.Fatalf("want %s, got %v", tsaudit.ErrUnknownPID, err)
	}
}

func TestNoPCRRejected(t *testing.T) {
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	b.AddPayload(b.Opt.Media[0].PID)
	_, err := tsaudit.Audit(b.Bytes(), 1000)
	if err == nil || err.Code != tsaudit.ErrNoPCR {
		t.Fatalf("want %s, got %v", tsaudit.ErrNoPCR, err)
	}
}

func TestInvalidGapParam(t *testing.T) {
	for _, g := range []int{0, -1, 10001} {
		if _, err := tsaudit.Audit(validFragment(), g); err == nil {
			t.Errorf("gap %d must be rejected", g)
		}
	}
}

func TestErrorCarriesPacketAndPID(t *testing.T) {
	b := tsbuild.New()
	b.AddPAT()
	b.AddPMT()
	b.AddPayload(0x0200) // packet 2, unknown PID
	_, err := tsaudit.Audit(b.Bytes(), 1000)
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Packet != 2 || err.PID != 0x0200 {
		t.Errorf("location = packet %d pid %#x, want 2 / 0x200", err.Packet, err.PID)
	}
}
