package tsaudit

import "fmt"

// Stable error codes returned for every failed audit.
const (
	ErrBodyTooLarge          = "TS_BODY_TOO_LARGE"
	ErrEmptyBody             = "TS_EMPTY_BODY"
	ErrNotPacketAligned      = "TS_NOT_PACKET_ALIGNED"
	ErrBadSyncByte           = "TS_BAD_SYNC_BYTE"
	ErrTransportError        = "TS_TRANSPORT_ERROR"
	ErrScrambled             = "TS_SCRAMBLED"
	ErrDiscontinuity         = "TS_DISCONTINUITY_FLAG"
	ErrMultiProgram          = "TS_MULTI_PROGRAM"
	ErrNoProgram             = "TS_NO_PROGRAM"
	ErrNoPCR                 = "TS_NO_PCR"
	ErrPATNotFound           = "TS_PAT_NOT_FOUND"
	ErrPMTNotFound           = "TS_PMT_NOT_FOUND"
	ErrPATSectionSpansPacket = "TS_PAT_SECTION_SPANS_PACKET"
	ErrPMTSectionSpansPacket = "TS_PMT_SECTION_SPANS_PACKET"
	ErrSectionSyntax         = "TS_SECTION_SYNTAX"
	ErrSectionPointer        = "TS_SECTION_POINTER"
	ErrSectionTruncated      = "TS_SECTION_TRUNCATED"
	ErrPATTableID            = "TS_PAT_TABLE_ID"
	ErrPMTTableID            = "TS_PMT_TABLE_ID"
	ErrSectionCRC            = "TS_SECTION_CRC"
	ErrPATVersionMismatch    = "TS_PAT_VERSION_MISMATCH"
	ErrPMTVersionMismatch    = "TS_PMT_VERSION_MISMATCH"
	ErrBadSectionLength      = "TS_BAD_SECTION_LENGTH"
	ErrUnknownPID            = "TS_UNKNOWN_PID"
	ErrCCGap                 = "TS_CC_GAP"
	ErrCCDuplicatePayload    = "TS_CC_DUPLICATE_WITH_PAYLOAD"
	ErrPCROnWrongPID         = "TS_PCR_ON_WRONG_PID"
	ErrPCRNoBase             = "TS_PCR_WITHOUT_BASE"
	ErrPCRReversed           = "TS_PCR_REVERSED"
	ErrPCRGapExceeded        = "TS_PCR_GAP_EXCEEDED"
	ErrPESNotFound           = "TS_PES_NOT_FOUND"
	ErrPESMissingPUSI        = "TS_PES_MISSING_PUSI"
	ErrPESEarlyStart         = "TS_PES_EARLY_START"
	ErrPESHeaderShort        = "TS_PES_HEADER_SHORT"
	ErrPESBadPrefix          = "TS_PES_BAD_PREFIX"
	ErrPESZeroLength         = "TS_PES_ZERO_LENGTH"
	ErrPESTrailingBytes      = "TS_PES_TRAILING_BYTES"
	ErrPESTruncated          = "TS_PES_TRUNCATED"
	ErrInternal              = "TS_INTERNAL"

	// Request-level codes (never tied to a packet).
	ErrMethodNotAllowed     = "TS_METHOD_NOT_ALLOWED"
	ErrUnsupportedMediaType = "TS_UNSUPPORTED_MEDIA_TYPE"
	ErrMissingMaxPcrGap     = "TS_MISSING_MAX_PCR_GAP"
	ErrInvalidMaxPcrGap     = "TS_INVALID_MAX_PCR_GAP"
	ErrInvalidPESParam      = "TS_INVALID_PES_PARAM"
	ErrBodyReadFailed       = "TS_BODY_READ_FAILED"
)

// AuditError identifies a single rule failure. Packet is the 0-based index of
// the offending 188-byte packet; PID is the related transport PID (or -1 when
// the failure is not tied to a PID).
type AuditError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Packet  int    `json:"packet"`
	PID     int    `json:"pid"`
}

func (e *AuditError) Error() string {
	return fmt.Sprintf("%s at packet %d pid 0x%04x: %s", e.Code, e.Packet, e.PID, e.Message)
}

func auditError(code, message string, packet, pid int) *AuditError {
	return &AuditError{Code: code, Message: message, Packet: packet, PID: pid}
}
