package tsaudit

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// HTTPError is a request-level failure distinct from an AuditError.
type HTTPError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// AuditHandler serves POST /api/mpegts/audit.
type AuditHandler struct{}

func (AuditHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	writeErr := func(status int, code, msg string, packet, pid *int) {
		body := map[string]any{
			"ok":    false,
			"error": HTTPError{Code: code, Message: msg},
		}
		if packet != nil {
			body["packet"] = *packet
		}
		if pid != nil {
			body["pid"] = *pid
		}
		writeJSON(w, status, body)
	}

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeErr(http.StatusMethodNotAllowed, ErrMethodNotAllowed, "use POST", nil, nil)
		return
	}
	if mt := r.Header.Get("Content-Type"); !strings.HasPrefix(strings.ToLower(strings.TrimSpace(mt)), "application/octet-stream") {
		writeErr(http.StatusUnsupportedMediaType, ErrUnsupportedMediaType,
			"Content-Type must be application/octet-stream", nil, nil)
		return
	}

	rawGap := r.URL.Query().Get("maxPcrGapMs")
	if rawGap == "" {
		writeErr(http.StatusBadRequest, ErrMissingMaxPcrGap,
			"query parameter maxPcrGapMs is required", nil, nil)
		return
	}
	gap, err := strconv.Atoi(rawGap)
	if err != nil || gap < 1 || gap > 10000 {
		writeErr(http.StatusBadRequest, ErrInvalidMaxPcrGap,
			"maxPcrGapMs must be an integer between 1 and 10000", nil, nil)
		return
	}

	// Optional bounded-PES audit layer: only "bounded" is a valid value; any
	// other present value (including an empty one) is a request error.
	pesBounded := false
	if values, present := r.URL.Query()["pes"]; present {
		for _, v := range values {
			if v != "bounded" {
				writeErr(http.StatusBadRequest, ErrInvalidPESParam,
					`query parameter pes only accepts "bounded"`, nil, nil)
				return
			}
		}
		pesBounded = true
	}

	// One extra byte lets us distinguish exactly 8 MiB from a too-large body.
	data, err := io.ReadAll(io.LimitReader(r.Body, MaxBodyBytes+1))
	if err != nil {
		writeErr(http.StatusBadRequest, ErrBodyReadFailed, "could not read request body", nil, nil)
		return
	}
	if len(data) > MaxBodyBytes {
		pkt := MaxBodyBytes / packetSize
		writeErr(http.StatusRequestEntityTooLarge, ErrBodyTooLarge,
			"body exceeds 8 MiB", &pkt, nil)
		return
	}

	report, auditErr := AuditPESBounded(data, gap, pesBounded)
	if auditErr != nil {
		var packet, pid *int
		if auditErr.Packet >= 0 {
			p := auditErr.Packet
			packet = &p
		}
		if auditErr.PID >= 0 {
			v := auditErr.PID
			pid = &v
		}
		writeErr(http.StatusUnprocessableEntity, auditErr.Code, auditErr.Message, packet, pid)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "report": report})
}

// HealthHandler answers container health checks.
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
