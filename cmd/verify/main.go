// Command verify is the one-shot verification service: it runs the Go tests,
// builds the server binary, starts it, waits for /healthz, exercises the audit
// API with legal and deliberately broken streams, and exits non-zero if any
// stage fails. It is self-contained and can be re-run from a clean checkout.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"mpegtsaudit/internal/tsbuild"
)

func main() {
	code := run()
	if code != 0 {
		fmt.Println("\nVERIFY: FAILED")
	} else {
		fmt.Println("\nVERIFY: ALL CHECKS PASSED")
	}
	os.Exit(code)
}

type check struct {
	name string
	fn   func() error
}

func run() int {
	steps := []struct {
		name string
		fn   func() error
	}{
		{"go vet", func() error { return runTool("go", "vet", "./...") }},
		{"go test", func() error { return runTool("go", "test", "-count=1", "./...") }},
		{"go build", buildApp},
	}
	for _, s := range steps {
		fmt.Printf("==> %s\n", s.name)
		if err := s.fn(); err != nil {
			fmt.Printf("    FAIL: %v\n", err)
			return 1
		}
		fmt.Println("    ok")
	}

	port, err := freePort()
	if err != nil {
		fmt.Printf("could not pick a port: %v\n", err)
		return 1
	}

	// AUDIT_BASE_URL targets an already-running server (used inside Docker
	// Compose after the app healthcheck passes). When unset, verify starts a
	// freshly built server itself, keeping the command self-contained.
	base := os.Getenv("AUDIT_BASE_URL")
	var srv *serverProc
	if base == "" {
		srv, err = startServer(port)
		if err != nil {
			fmt.Printf("could not start server: %v\n", err)
			return 1
		}
		defer srv.stop()
		base = fmt.Sprintf("http://127.0.0.1:%d", port)
	}

	fmt.Printf("==> waiting for health (%s)\n", base)
	if err := waitHealthy(base, 30*time.Second); err != nil {
		fmt.Printf("    FAIL: %v\n", err)
		return 1
	}
	fmt.Println("    healthy")

	cases := smokeCases(base)
	failed := 0
	for _, c := range cases {
		fmt.Printf("==> smoke: %s\n", c.name)
		if err := c.fn(); err != nil {
			fmt.Printf("    FAIL: %v\n", err)
			failed++
			continue
		}
		fmt.Println("    ok")
	}
	if failed > 0 {
		fmt.Printf("%d smoke case(s) failed\n", failed)
		return 1
	}
	return 0
}

func runTool(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func buildApp() error {
	out, err := filepath.Abs(filepath.Join(os.TempDir(), fmt.Sprintf("mpegts-audit-%d", os.Getpid())))
	if err != nil {
		return err
	}
	build := exec.Command("go", "build", "-o", out, "./cmd/server")
	build.Stdout = os.Stdout
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		return err
	}
	binaryPath = out
	return nil
}

var binaryPath string

type serverProc struct {
	cmd *exec.Cmd
}

func startServer(port int) (*serverProc, error) {
	cmd := exec.Command(binaryPath)
	cmd.Env = append(os.Environ(), fmt.Sprintf("PORT=%d", port))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &serverProc{cmd: cmd}, nil
}

func (s *serverProc) stop() {
	if s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
		_ = s.cmd.Wait()
	}
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func waitHealthy(base string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: time.Second}
	url := base + "/healthz"
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return nil
			}
			_ = body
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("server did not become healthy within %s", timeout)
}

func smokeCases(base string) []check {
	good := func() []byte {
		b := tsbuild.New()
		b.AddPAT()
		b.AddPMT()
		for i := 0; i < 4; i++ {
			b.AddPCR(b.Opt.PCRPID, int64(i)*40*27000)
			b.AddPayload(b.Opt.Media[0].PID)
			b.AddPayload(b.Opt.Media[1].PID)
		}
		return b.Bytes()
	}

	auditQuery := func(body []byte, ctype, query string) (*http.Response, map[string]any, error) {
		req, _ := http.NewRequest(http.MethodPost, base+"/api/mpegts/audit?"+query, bytes.NewReader(body))
		req.Header.Set("Content-Type", ctype)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, nil, err
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		var decoded map[string]any
		_ = json.Unmarshal(raw, &decoded)
		return resp, decoded, nil
	}

	audit := func(body []byte, ctype string) (*http.Response, map[string]any, error) {
		return auditQuery(body, ctype, "maxPcrGapMs=1000")
	}

	expectStatus := func(resp *http.Response, want int) error {
		if resp.StatusCode != want {
			return fmt.Errorf("status=%d want %d", resp.StatusCode, want)
		}
		return nil
	}

	return []check{
		{
			name: "legal stream accepted with full report",
			fn: func() error {
				resp, body, err := audit(good(), "application/octet-stream")
				if err != nil {
					return err
				}
				if err := expectStatus(resp, http.StatusOK); err != nil {
					return err
				}
				if body["ok"] != true {
					return fmt.Errorf("ok=%v", body["ok"])
				}
				rep := body["report"].(map[string]any)
				if rep["programNumber"].(float64) != 1 {
					return fmt.Errorf("programNumber=%v", rep["programNumber"])
				}
				if rep["packetCount"].(float64) != 14 {
					return fmt.Errorf("packetCount=%v", rep["packetCount"])
				}
				if rep["durationMs"].(float64) != 120 {
					return fmt.Errorf("durationMs=%v", rep["durationMs"])
				}
				if rep["payloadBytes"].(float64) != 8*184 {
					return fmt.Errorf("payloadBytes=%v", rep["payloadBytes"])
				}
				return nil
			},
		},
		{
			name: "bad sync byte rejected with packet and pid",
			fn: func() error {
				d := good()
				d[0] = 0x00
				resp, body, err := audit(d, "application/octet-stream")
				if err != nil {
					return err
				}
				if err := expectStatus(resp, http.StatusUnprocessableEntity); err != nil {
					return err
				}
				return expectCode(body, "TS_BAD_SYNC_BYTE", 0)
			},
		},
		{
			name: "scrambled packet rejected",
			fn: func() error {
				b := tsbuild.New()
				b.AddPAT().AddPMT()
				b.AddPayload(b.Opt.Media[0].PID)
				b.MutateLast(func(buf []byte) { buf[3] |= 0x40 })
				resp, body, err := audit(b.Bytes(), "application/octet-stream")
				if err != nil {
					return err
				}
				if err := expectStatus(resp, http.StatusUnprocessableEntity); err != nil {
					return err
				}
				return expectCode(body, "TS_SCRAMBLED", 2)
			},
		},
		{
			name: "continuity counter gap rejected",
			fn: func() error {
				b := tsbuild.New()
				b.AddPAT().AddPMT()
				pid := b.Opt.Media[0].PID
				b.AddPayload(pid).AddPayload(pid)
				b.MutateLast(func(buf []byte) { buf[3] = (buf[3] & 0xF0) | 9 })
				resp, body, err := audit(b.Bytes(), "application/octet-stream")
				if err != nil {
					return err
				}
				if err := expectStatus(resp, http.StatusUnprocessableEntity); err != nil {
					return err
				}
				return expectCode(body, "TS_CC_GAP", 3)
			},
		},
		{
			name: "PCR reversal rejected",
			fn: func() error {
				b := tsbuild.New()
				b.AddPAT().AddPMT()
				b.AddPCR(b.Opt.PCRPID, 100*27000)
				b.AddPayload(b.Opt.Media[0].PID)
				b.AddPCR(b.Opt.PCRPID, 80*27000)
				resp, body, err := audit(b.Bytes(), "application/octet-stream")
				if err != nil {
					return err
				}
				if err := expectStatus(resp, http.StatusUnprocessableEntity); err != nil {
					return err
				}
				return expectCode(body, "TS_PCR_REVERSED", 4)
			},
		},
		{
			name: "multi-program PAT rejected",
			fn: func() error {
				b := tsbuild.New()
				b.AddPATWith(b.MultiPATSection(map[int]int{1: 0x1000, 2: 0x1001}))
				resp, body, err := audit(b.Bytes(), "application/octet-stream")
				if err != nil {
					return err
				}
				if err := expectStatus(resp, http.StatusUnprocessableEntity); err != nil {
					return err
				}
				return expectCode(body, "TS_MULTI_PROGRAM", 0)
			},
		},
		{
			name: "corrupt section CRC rejected",
			fn: func() error {
				b := tsbuild.New()
				b.AddPAT()
				b.MutateLast(func(buf []byte) { buf[12] ^= 0x01 })
				resp, body, err := audit(b.Bytes(), "application/octet-stream")
				if err != nil {
					return err
				}
				if err := expectStatus(resp, http.StatusUnprocessableEntity); err != nil {
					return err
				}
				return expectCode(body, "TS_SECTION_CRC", 0)
			},
		},
		{
			name: "PCR gap over limit rejected",
			fn: func() error {
				b := tsbuild.New()
				b.AddPAT().AddPMT()
				b.AddPCR(b.Opt.PCRPID, 0)
				b.AddPayload(b.Opt.Media[0].PID)
				b.AddPCR(b.Opt.PCRPID, 5000*27000)
				resp, body, err := audit(b.Bytes(), "application/octet-stream")
				if err != nil {
					return err
				}
				if err := expectStatus(resp, http.StatusUnprocessableEntity); err != nil {
					return err
				}
				return expectCode(body, "TS_PCR_GAP_EXCEEDED", 4)
			},
		},
		{
			name: "bounded PES spanning packets accepted",
			fn: func() error {
				b := tsbuild.New()
				b.AddPAT().AddPMT()
				for i := 0; i < 3; i++ {
					b.AddPCR(b.Opt.PCRPID, int64(i)*40*27000)
					b.AddPES(b.Opt.Media[0].PID, 0xE0, 400) // spans 3 TS packets
					b.AddPES(b.Opt.Media[1].PID, 0xC0, 100) // single packet
				}
				resp, body, err := auditQuery(b.Bytes(), "application/octet-stream", "maxPcrGapMs=1000&pes=bounded")
				if err != nil {
					return err
				}
				if err := expectStatus(resp, http.StatusOK); err != nil {
					return err
				}
				rep := body["report"].(map[string]any)
				want := map[int]struct{ count, bytes float64 }{
					b.Opt.Media[0].PID: {3, 3 * 406},
					b.Opt.Media[1].PID: {3, 3 * 106},
				}
				for _, m := range rep["media"].([]any) {
					entry := m.(map[string]any)
					w, ok := want[int(entry["pid"].(float64))]
					if !ok {
						return fmt.Errorf("unexpected media pid %v", entry["pid"])
					}
					if entry["pesCount"].(float64) != w.count || entry["pesBytes"].(float64) != w.bytes {
						return fmt.Errorf("pid %v: pesCount=%v pesBytes=%v, want %v/%v",
							entry["pid"], entry["pesCount"], entry["pesBytes"], w.count, w.bytes)
					}
				}
				return nil
			},
		},
		{
			name: "early PES restart rejected",
			fn: func() error {
				b := tsbuild.New()
				b.AddPAT().AddPMT()
				b.AddPCR(b.Opt.PCRPID, 0)
				hdr := tsbuild.PESBytes(0xE0, 1000) // declares 1006 bytes
				b.AddPayloadChunk(b.Opt.Media[0].PID, true, hdr[:6])
				b.AddPES(b.Opt.Media[0].PID, 0xE0, 20) // PUSI while bytes still owed
				resp, body, err := auditQuery(b.Bytes(), "application/octet-stream", "maxPcrGapMs=1000&pes=bounded")
				if err != nil {
					return err
				}
				if err := expectStatus(resp, http.StatusUnprocessableEntity); err != nil {
					return err
				}
				return expectCode(body, "TS_PES_EARLY_START", 4)
			},
		},
		{
			name: "truncated PES stream rejected",
			fn: func() error {
				b := tsbuild.New()
				b.AddPAT().AddPMT()
				b.AddPCR(b.Opt.PCRPID, 0)
				hdr := tsbuild.PESBytes(0xE0, 1000) // declares 1006 bytes, 6 delivered
				b.AddPayloadChunk(b.Opt.Media[0].PID, true, hdr[:6])
				b.AddPES(b.Opt.Media[1].PID, 0xC0, 100)
				resp, body, err := auditQuery(b.Bytes(), "application/octet-stream", "maxPcrGapMs=1000&pes=bounded")
				if err != nil {
					return err
				}
				if err := expectStatus(resp, http.StatusUnprocessableEntity); err != nil {
					return err
				}
				return expectCode(body, "TS_PES_TRUNCATED", 3)
			},
		},
		{
			name: "invalid pes parameter rejected",
			fn: func() error {
				resp, body, err := auditQuery(good(), "application/octet-stream", "maxPcrGapMs=1000&pes=full")
				if err != nil {
					return err
				}
				if err := expectStatus(resp, http.StatusBadRequest); err != nil {
					return err
				}
				return expectCodeAnyPacket(body, "TS_INVALID_PES_PARAM")
			},
		},
		{
			name: "body over 8 MiB rejected",
			fn: func() error {
				big := make([]byte, (8<<20)+188)
				resp, body, err := audit(big, "application/octet-stream")
				if err != nil {
					return err
				}
				if err := expectStatus(resp, http.StatusRequestEntityTooLarge); err != nil {
					return err
				}
				return expectCodeAnyPacket(body, "TS_BODY_TOO_LARGE")
			},
		},
		{
			name: "missing maxPcrGapMs rejected",
			fn: func() error {
				req, _ := http.NewRequest(http.MethodPost, base+"/api/mpegts/audit", bytes.NewReader(good()))
				req.Header.Set("Content-Type", "application/octet-stream")
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					return err
				}
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusBadRequest {
					return fmt.Errorf("status=%d want 400", resp.StatusCode)
				}
				return nil
			},
		},
		{
			name: "wrong content type rejected",
			fn: func() error {
				resp, _, err := audit(good(), "text/plain")
				if err != nil {
					return err
				}
				return expectStatus(resp, http.StatusUnsupportedMediaType)
			},
		},
		{
			name: "health endpoint reports ok",
			fn: func() error {
				resp, err := http.Get(base + "/healthz")
				if err != nil {
					return err
				}
				defer resp.Body.Close()
				return expectStatus(resp, http.StatusOK)
			},
		},
	}
}

func expectCode(body map[string]any, code string, packet int) error {
	if err := expectCodeAnyPacket(body, code); err != nil {
		return err
	}
	if int(body["packet"].(float64)) != packet {
		return fmt.Errorf("packet=%v want %d", body["packet"], packet)
	}
	if _, partial := body["report"]; partial {
		return fmt.Errorf("partial report present on failure")
	}
	return nil
}

func expectCodeAnyPacket(body map[string]any, code string) error {
	errObj, ok := body["error"].(map[string]any)
	if !ok {
		return fmt.Errorf("no error object: %v", body)
	}
	if errObj["code"] != code {
		return fmt.Errorf("code=%v want %s", errObj["code"], code)
	}
	if body["ok"] != false {
		return fmt.Errorf("ok must be false")
	}
	return nil
}
