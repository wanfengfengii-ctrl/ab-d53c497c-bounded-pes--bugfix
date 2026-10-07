package tsaudit_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"mpegtsaudit/internal/tsaudit"
)

func doAudit(t *testing.T, body []byte, query, ctype string) (int, map[string]any) {
	t.Helper()
	srv := httptest.NewServer(tsaudit.AuditHandler{})
	defer srv.Close()

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/mpegts/audit?"+query, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var decoded map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	return resp.StatusCode, decoded
}

func TestHTTPSuccess(t *testing.T) {
	status, body := doAudit(t, validFragment(), "maxPcrGapMs=1000", "application/octet-stream")
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v", status, body)
	}
	if body["ok"] != true {
		t.Fatalf("ok flag = %v", body["ok"])
	}
	rep := body["report"].(map[string]any)
	if rep["programNumber"].(float64) != 1 {
		t.Errorf("programNumber = %v", rep["programNumber"])
	}
}

func TestHTTPRuleFailureShape(t *testing.T) {
	d := validFragment()
	d[0] = 0x00 // bad sync
	status, body := doAudit(t, d, "maxPcrGapMs=1000", "application/octet-stream")
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d", status)
	}
	if body["ok"] != false {
		t.Fatalf("ok must be false, got %v", body["ok"])
	}
	errObj := body["error"].(map[string]any)
	if errObj["code"] != tsaudit.ErrBadSyncByte {
		t.Errorf("code = %v", errObj["code"])
	}
	if _, ok := body["report"]; ok {
		t.Fatal("partial report must not be returned on failure")
	}
	if body["packet"].(float64) != 0 {
		t.Errorf("packet = %v", body["packet"])
	}
}

func TestHTTPBadParams(t *testing.T) {
	cases := []struct {
		name   string
		query  string
		status int
		code   string
	}{
		{"missing", "", http.StatusBadRequest, "TS_MISSING_MAX_PCR_GAP"},
		{"zero", "maxPcrGapMs=0", http.StatusBadRequest, "TS_INVALID_MAX_PCR_GAP"},
		{"huge", "maxPcrGapMs=99999", http.StatusBadRequest, "TS_INVALID_MAX_PCR_GAP"},
		{"nan", "maxPcrGapMs=abc", http.StatusBadRequest, "TS_INVALID_MAX_PCR_GAP"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, body := doAudit(t, validFragment(), tc.query, "application/octet-stream")
			if status != tc.status {
				t.Fatalf("status=%d body=%v", status, body)
			}
			if body["error"].(map[string]any)["code"] != tc.code {
				t.Fatalf("body=%v", body)
			}
		})
	}
}

func TestHTTPWrongContentType(t *testing.T) {
	status, _ := doAudit(t, validFragment(), "maxPcrGapMs=1000", "text/plain")
	if status != http.StatusUnsupportedMediaType {
		t.Fatalf("status=%d", status)
	}
}

func TestHTTPPESParamValues(t *testing.T) {
	cases := []struct {
		name   string
		query  string
		status int
		code   string
	}{
		{"bounded accepted", "maxPcrGapMs=1000&pes=bounded", http.StatusOK, ""},
		{"unknown value", "maxPcrGapMs=1000&pes=full", http.StatusBadRequest, tsaudit.ErrInvalidPESParam},
		{"empty value", "maxPcrGapMs=1000&pes=", http.StatusBadRequest, tsaudit.ErrInvalidPESParam},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, body := doAudit(t, pesFragment(), tc.query, "application/octet-stream")
			if status != tc.status {
				t.Fatalf("status=%d body=%v", status, body)
			}
			if tc.code != "" && body["error"].(map[string]any)["code"] != tc.code {
				t.Fatalf("body=%v", body)
			}
		})
	}
}

func TestHTTPPESBoundedReport(t *testing.T) {
	status, body := doAudit(t, pesFragment(), "maxPcrGapMs=1000&pes=bounded", "application/octet-stream")
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v", status, body)
	}
	media := body["report"].(map[string]any)["media"].([]any)
	if len(media) != 2 {
		t.Fatalf("media entries = %d", len(media))
	}
	entry := media[0].(map[string]any)
	if entry["pesCount"].(float64) != 3 {
		t.Errorf("pesCount = %v, want 3", entry["pesCount"])
	}
	if entry["pesBytes"].(float64) != 3*406 {
		t.Errorf("pesBytes = %v, want %d", entry["pesBytes"], 3*406)
	}
}

func TestHTTPPESOmittedKeepsLegacyShape(t *testing.T) {
	status, body := doAudit(t, validFragment(), "maxPcrGapMs=1000", "application/octet-stream")
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v", status, body)
	}
	media := body["report"].(map[string]any)["media"].([]any)
	for _, m := range media {
		entry := m.(map[string]any)
		if _, ok := entry["pesCount"]; ok {
			t.Errorf("pesCount must be absent without pes=bounded: %v", entry)
		}
		if _, ok := entry["pesBytes"]; ok {
			t.Errorf("pesBytes must be absent without pes=bounded: %v", entry)
		}
	}
}

func TestHTTPPESBoundedViolation(t *testing.T) {
	// validFragment's media packets are pattern payloads without PUSI: legal
	// for the base audit, rejected once pes=bounded is requested.
	status, body := doAudit(t, validFragment(), "maxPcrGapMs=1000&pes=bounded", "application/octet-stream")
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d body=%v", status, body)
	}
	if body["error"].(map[string]any)["code"] != tsaudit.ErrPESMissingPUSI {
		t.Fatalf("body=%v", body)
	}
	if body["packet"].(float64) != 3 {
		t.Errorf("packet = %v, want 3", body["packet"])
	}
	if _, ok := body["report"]; ok {
		t.Fatal("partial report must not be returned on failure")
	}
}

func TestHTTPPESBoundedFirstViolationWinsOverLaterBadSync(t *testing.T) {
	// Packet 3 is the first media payload without PUSI; packet 4 carries a
	// corrupt sync byte. With pes=bounded the earlier bounded-PES violation
	// must be the single verdict, and the later header error cannot mask it.
	stream := multiErrorBoundedFragment()
	status, body := doAudit(t, stream, "maxPcrGapMs=1000&pes=bounded", "application/octet-stream")
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d body=%v", status, body)
	}
	if body["ok"] != false {
		t.Fatalf("ok = %v, want false", body["ok"])
	}
	if body["error"].(map[string]any)["code"] != tsaudit.ErrPESMissingPUSI {
		t.Fatalf("code=%v want %s", body["error"], tsaudit.ErrPESMissingPUSI)
	}
	if body["packet"].(float64) != 3 {
		t.Errorf("packet = %v, want 3", body["packet"])
	}
	if body["pid"].(float64) != 0x0101 {
		t.Errorf("pid = %v, want 257", body["pid"])
	}
	if _, ok := body["report"]; ok {
		t.Fatal("partial report must not be returned on failure")
	}

	// Compatibility: omitting pes keeps the legacy verdict order, so the
	// packet-header corruption is what the base audit reports.
	status, body = doAudit(t, stream, "maxPcrGapMs=1000", "application/octet-stream")
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("legacy status=%d body=%v", status, body)
	}
	if body["error"].(map[string]any)["code"] != tsaudit.ErrBadSyncByte {
		t.Fatalf("legacy code=%v want %s", body["error"], tsaudit.ErrBadSyncByte)
	}
	if body["packet"].(float64) != 4 {
		t.Errorf("legacy packet = %v, want 4", body["packet"])
	}
	if _, ok := body["pid"]; ok {
		t.Errorf("bad sync byte carries no PID, got %v", body["pid"])
	}
}

func TestHTTPTooLarge(t *testing.T) {
	big := make([]byte, tsaudit.MaxBodyBytes+188)
	for i := range big {
		big[i] = 0xFF
	}
	big[0] = 0x47
	status, body := doAudit(t, big, "maxPcrGapMs=1000", "application/octet-stream")
	if status != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d body=%v", status, body)
	}
	if body["error"].(map[string]any)["code"] != tsaudit.ErrBodyTooLarge {
		t.Fatalf("body=%v", body)
	}
}
