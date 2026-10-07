package main

import (
	"log"
	"net/http"
	"os"

	"mpegtsaudit/internal/tsaudit"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	mux := http.NewServeMux()
	mux.Handle("/api/mpegts/audit", tsaudit.AuditHandler{})
	mux.HandleFunc("/healthz", tsaudit.HealthHandler)

	addr := ":" + port
	log.Printf("mpegts-audit listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}
