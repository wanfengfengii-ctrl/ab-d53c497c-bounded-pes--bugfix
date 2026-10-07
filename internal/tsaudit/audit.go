package tsaudit

import "sort"

// MaxBodyBytes is the largest accepted fragment: 8 MiB.
const MaxBodyBytes = 8 << 20

// pcrCycle is the 33-bit PCR base wraparound expressed in 27 MHz units
// (base ticks * 300 extension ticks).
const pcrCycle = int64(1) << 33 * 300

// PCRRef locates one PCR value in the fragment.
type PCRRef struct {
	Packet     int   `json:"packet"`
	Base       int64 `json:"base"`
	Extension  int   `json:"extension"`
	Value27MHz int64 `json:"value27mhz"`
}

// MediaPIDStats carries per-PID payload accounting. PESCount and PESBytes
// are only populated when the bounded-PES audit layer is enabled; they are
// omitted from the JSON report otherwise.
type MediaPIDStats struct {
	PID          int    `json:"pid"`
	PacketCount  int    `json:"packetCount"`
	PayloadBytes int64  `json:"payloadBytes"`
	PESCount     *int64 `json:"pesCount,omitempty"`
	PESBytes     *int64 `json:"pesBytes,omitempty"`
}

// Report is the all-or-nothing success result.
type Report struct {
	ProgramNumber int             `json:"programNumber"`
	PMTPID        int             `json:"pmtPID"`
	PCRPID        int             `json:"pcrPID"`
	MediaPIDs     []int           `json:"mediaPIDs"`
	PacketCount   int             `json:"packetCount"`
	FirstPCR      *PCRRef         `json:"firstPCR"`
	LastPCR       *PCRRef         `json:"lastPCR"`
	Duration27MHz int64           `json:"duration27mhz"`
	DurationMs    float64         `json:"durationMs"`
	PayloadBytes  int64           `json:"payloadBytes"`
	Media         []MediaPIDStats `json:"media"`
}

type ccState struct {
	started bool
	cc      int
}

// Audit validates a raw MPEG-TS fragment. On success it returns a Report; on
// the first violated rule it returns an AuditError and no partial results.
func Audit(data []byte, maxPcrGapMs int) (*Report, *AuditError) {
	return audit(data, maxPcrGapMs, false)
}

// AuditPESBounded behaves exactly like Audit when pesBounded is false. When
// true it additionally enforces bounded-PES framing on every PMT media PID:
// each payload must carry complete PES packets (00 00 01 prefix, stream_id,
// non-zero PES_packet_length) aligned to payload boundaries.
func AuditPESBounded(data []byte, maxPcrGapMs int, pesBounded bool) (*Report, *AuditError) {
	return audit(data, maxPcrGapMs, pesBounded)
}

func audit(data []byte, maxPcrGapMs int, pesBounded bool) (*Report, *AuditError) {
	if maxPcrGapMs < 1 || maxPcrGapMs > 10000 {
		return nil, auditError(ErrInvalidMaxPcrGap, "maxPcrGapMs must be between 1 and 10000", -1, -1)
	}
	if len(data) == 0 {
		return nil, auditError(ErrEmptyBody, "request body is empty", -1, -1)
	}
	if len(data)%packetSize != 0 {
		return nil, auditError(ErrNotPacketAligned, "body length is not a multiple of 188 bytes", len(data)/packetSize, -1)
	}
	n := len(data) / packetSize
	pkts := make([]*Packet, n)

	// ---- Pass A: per-packet header rules + PAT collection ----------------
	// With pes=bounded the verdict must be the earliest violation in input
	// order, so a fatal header/PSI error does not abort the audit immediately:
	// it is remembered in earlyErr, parsing stops at that packet, and the
	// later passes examine only the valid prefix. A concrete violation located
	// before earlyErr then wins (see Pass C); otherwise earlyErr is returned.
	// Without the bounded layer the first error still aborts, exactly as before.
	var earlyErr *AuditError
	parsed := n
	var pats []*tableSection
	for i := 0; i < n; i++ {
		off := i * packetSize
		raw := data[off : off+packetSize : off+packetSize]
		p, err := parsePacket(raw, i)
		if err != nil {
			if !pesBounded {
				return nil, err
			}
			earlyErr, parsed = err, i
			break
		}
		pkts[i] = p

		if p.HasAdaptation && len(p.Adaptation) > 0 && p.Adaptation[0]&afFlagDiscontinuity != 0 {
			err := auditError(ErrDiscontinuity, "adaptation field discontinuity indicator set", i, p.PID)
			if !pesBounded {
				return nil, err
			}
			earlyErr, parsed = err, i
			break
		}

		if p.PID == pidPAT {
			if !p.PUSI {
				err := auditError(ErrPATSectionSpansPacket, "PAT continuation packet: section is not contained in one packet", i, p.PID)
				if !pesBounded {
					return nil, err
				}
				earlyErr, parsed = err, i
				break
			}
			sec, err := parseTablePacket(raw, p, i, 0x00, ErrPATTableID, ErrPATSectionSpansPacket, ErrSectionTruncated)
			if err != nil {
				if !pesBounded {
					return nil, err
				}
				earlyErr, parsed = err, i
				break
			}
			pats = append(pats, sec)
		}
	}

	if len(pats) == 0 {
		if earlyErr != nil {
			return nil, earlyErr
		}
		return nil, auditError(ErrPATNotFound, "no PAT found on PID 0x0000", 0, pidPAT)
	}
	pat := pats[0]
	for _, s := range pats[1:] {
		if s.version != pat.version || !bytesEqual(s.raw, pat.raw) {
			return nil, auditError(ErrPATVersionMismatch, "PAT sections must share one version and identical content", s.packet, pidPAT)
		}
	}
	if len(pat.programs) == 0 {
		return nil, auditError(ErrNoProgram, "PAT declares no program", pat.packet, pidPAT)
	}
	if len(pat.programs) > 1 {
		return nil, auditError(ErrMultiProgram, "PAT declares more than one program", pat.packet, pidPAT)
	}
	prog := pat.programs[0]
	if prog.pid == pidPAT || prog.pid == 0x1FFF {
		return nil, auditError(ErrSectionSyntax, "PAT uses reserved PMT PID", pat.packet, pidPAT)
	}

	// ---- Pass B: PMT collection on the PAT-signalled PID -----------------
	// Only packets with valid headers are inspected (parsed may stop short of
	// a deferred packet-header failure). PMT/PSI failures are located on the
	// signalling PID and always precede media payloads, so they keep their
	// immediate verdict even in bounded mode.
	var pmts []*tableSection
	for i := 0; i < parsed; i++ {
		p := pkts[i]
		if p.PID != prog.pid {
			continue
		}
		if !p.PUSI {
			return nil, auditError(ErrPMTSectionSpansPacket, "PMT continuation packet: section is not contained in one packet", i, p.PID)
		}
		raw := data[i*packetSize : i*packetSize+packetSize]
		sec, err := parseTablePacket(raw, p, i, 0x02, ErrPMTTableID, ErrPMTSectionSpansPacket, ErrSectionTruncated)
		if err != nil {
			return nil, err
		}
		pmts = append(pmts, sec)
	}
	if len(pmts) == 0 {
		if earlyErr != nil {
			return nil, earlyErr
		}
		return nil, auditError(ErrPMTNotFound, "no PMT found on the PAT-signalled PID", 0, prog.pid)
	}
	pmt := pmts[0]
	for _, s := range pmts[1:] {
		if s.version != pmt.version || !bytesEqual(s.raw, pmt.raw) {
			return nil, auditError(ErrPMTVersionMismatch, "PMT sections must share one version and identical content", s.packet, prog.pid)
		}
	}
	if pmtProgramNumber(pmt) != prog.number {
		return nil, auditError(ErrSectionSyntax, "PMT program_number does not match PAT", pmt.packet, prog.pid)
	}
	if pmt.pcrPID == 0x1FFF {
		return nil, auditError(ErrNoPCR, "PMT declares no PCR PID (0x1FFF)", pmt.packet, prog.pid)
	}

	mediaSet := map[int]bool{}
	var mediaPIDs []int
	for _, pid := range pmt.mediaPIDs {
		if !mediaSet[pid] {
			mediaSet[pid] = true
			mediaPIDs = append(mediaPIDs, pid)
		}
	}
	sort.Ints(mediaPIDs)

	declared := map[int]bool{prog.pid: true, pmt.pcrPID: true}
	for _, pid := range mediaPIDs {
		declared[pid] = true
	}
	tracked := map[int]bool{pidPAT: true}
	for pid := range declared {
		tracked[pid] = true
	}

	// ---- Pass C: PID membership, continuity counters and PCR timeline ----
	cc := map[int]*ccState{}
	stats := map[int]*MediaPIDStats{}
	for _, pid := range mediaPIDs {
		stats[pid] = &MediaPIDStats{PID: pid}
	}
	pes := map[int]*pesState{}
	if pesBounded {
		for _, pid := range mediaPIDs {
			pes[pid] = &pesState{}
		}
	}

	var firstPCR, lastPCR *PCRRef
	var prevPCR, unwrappedPCR int64
	var pcrCount int
	var payloadTotal int64

	// fatal records a violation located at a concrete packet. In the legacy
	// path it is the verdict immediately. With pes=bounded it is kept only when
	// it is earlier than the violation already recorded; the caller then skips
	// the remaining per-packet checks. The smallest located violation becomes
	// the single verdict after the loop, so a later packet-header failure can
	// never mask an earlier bounded-PES (or other payload) violation.
	fatal := func(e *AuditError) bool {
		if !pesBounded {
			earlyErr = e
			return true
		}
		if earlyErr == nil || e.Packet < earlyErr.Packet {
			earlyErr = e
		}
		return false
	}

packetLoop:
	for i := 0; i < parsed; i++ {
		p := pkts[i]
		if p.PID == 0x1FFF { // null packets are stuffing and carry no semantics
			continue
		}
		if p.PID != pidPAT && !declared[p.PID] {
			if fatal(auditError(ErrUnknownPID, "packet on PID not declared by PAT/PMT", i, p.PID)) {
				return nil, earlyErr
			}
			continue
		}

		if v, hasFlag, ok := p.pcr(); hasFlag {
			if !ok {
				if fatal(auditError(ErrPCRNoBase, "PCR flag set but PCR field is truncated", i, p.PID)) {
					return nil, earlyErr
				}
				continue packetLoop
			}
			if p.PID != pmt.pcrPID {
				if fatal(auditError(ErrPCROnWrongPID, "PCR may only appear on the PMT-declared PCR PID", i, p.PID)) {
					return nil, earlyErr
				}
				continue packetLoop
			}
			ref := &PCRRef{Packet: i, Base: v / 300, Extension: int(v % 300), Value27MHz: v}
			if pcrCount == 0 {
				firstPCR, lastPCR = ref, ref
				unwrappedPCR = v
			} else {
				d := v - prevPCR
				if d < -pcrCycle/2 { // genuine 33-bit base wraparound
					d += pcrCycle
				}
				if d < 0 {
					if fatal(auditError(ErrPCRReversed, "PCR moved backwards after 33-bit unwrap", i, p.PID)) {
						return nil, earlyErr
					}
					continue packetLoop
				}
				if d > int64(maxPcrGapMs)*27000 {
					if fatal(auditError(ErrPCRGapExceeded, "PCR interval exceeds maxPcrGapMs", i, p.PID)) {
						return nil, earlyErr
					}
					continue packetLoop
				}
				unwrappedPCR += d
				ref.Value27MHz = unwrappedPCR
				ref.Base = unwrappedPCR / 300
				ref.Extension = int(unwrappedPCR % 300)
				lastPCR = ref
			}
			prevPCR = v
			pcrCount++
		}

		if tracked[p.PID] {
			st := cc[p.PID]
			if st == nil {
				st = &ccState{}
				cc[p.PID] = st
			}
			if st.started {
				if p.HasPayload {
					var ccErr *AuditError
					switch {
					case p.CC == st.cc:
						ccErr = auditError(ErrCCDuplicatePayload, "continuity counter repeated on a payload-bearing packet", i, p.PID)
					case p.CC != (st.cc+1)&0x0F:
						ccErr = auditError(ErrCCGap, "continuity counter did not increment modulo 16", i, p.PID)
					}
					if ccErr != nil {
						if fatal(ccErr) {
							return nil, earlyErr
						}
						continue packetLoop
					}
				} else if p.CC != st.cc {
					if fatal(auditError(ErrCCGap, "adaptation-only packet must keep the continuity counter unchanged", i, p.PID)) {
						return nil, earlyErr
					}
					continue packetLoop
				}
			}
			st.started = true
			st.cc = p.CC
		}

		if st := stats[p.PID]; st != nil && p.HasPayload {
			st.PacketCount++
			b := int64(packetSize - p.PayloadStart)
			st.PayloadBytes += b
			payloadTotal += b
		}

		if st := pes[p.PID]; st != nil && p.HasPayload {
			payload := data[i*packetSize+p.PayloadStart : (i+1)*packetSize]
			if err := st.consume(payload, p.PUSI, i, p.PID); err != nil {
				if fatal(err) {
					return nil, earlyErr
				}
			}
		}
	}

	// A violation located at a concrete packet always outranks end-of-stream
	// conditions such as a missing PCR or PES.
	if earlyErr != nil {
		return nil, earlyErr
	}

	if pcrCount == 0 {
		return nil, auditError(ErrNoPCR, "no PCR found on the PMT-declared PCR PID", 0, pmt.pcrPID)
	}

	// Bounded-PES end-of-stream rules: no incomplete PES may remain and every
	// media PID must have carried at least one complete PES.
	for _, pid := range mediaPIDs {
		if st := pes[pid]; st != nil {
			if err := st.finish(pid); err != nil {
				return nil, err
			}
		}
	}

	duration := int64(0)
	if pcrCount > 1 {
		duration = lastPCR.Value27MHz - firstPCR.Value27MHz
	}
	media := make([]MediaPIDStats, 0, len(mediaPIDs))
	for _, pid := range mediaPIDs {
		m := *stats[pid]
		if st := pes[pid]; st != nil {
			count, bytes := st.count, st.bytes
			m.PESCount = &count
			m.PESBytes = &bytes
		}
		media = append(media, m)
	}

	return &Report{
		ProgramNumber: prog.number,
		PMTPID:        prog.pid,
		PCRPID:        pmt.pcrPID,
		MediaPIDs:     mediaPIDs,
		PacketCount:   n,
		FirstPCR:      firstPCR,
		LastPCR:       lastPCR,
		Duration27MHz: duration,
		DurationMs:    float64(duration) / 27000,
		PayloadBytes:  payloadTotal,
		Media:         media,
	}, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func pmtProgramNumber(s *tableSection) int {
	return int(s.raw[3])<<8 | int(s.raw[4])
}
