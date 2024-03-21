package main

import (
	"gcpsudobot"
	"log"
	"log/slog"
	"net/http"
)

func main() {
	slog.Info("Starting http server on :8080...")
	http.HandleFunc("/ActionHandler", gcpsudobot.ActionHandler)
	http.HandleFunc("/SlashHandler", gcpsudobot.SlashHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
