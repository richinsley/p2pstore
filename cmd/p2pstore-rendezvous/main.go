// Command p2pstore-rendezvous runs the short-lived, in-memory HTTPS signaling
// helper used to introduce one p2pstore provider to one client.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/richinsley/p2pstore/signal/rendezvous"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8443", "listen address")
	certificate := flag.String("cert", "", "TLS certificate PEM")
	privateKey := flag.String("key", "", "TLS private key PEM")
	flag.Parse()
	if (*certificate == "") != (*privateKey == "") {
		fatal("--cert and --key must be supplied together")
	}
	if *certificate == "" && !loopbackAddress(*listen) {
		fatal("TLS is required when listening beyond loopback")
	}

	server := &http.Server{
		Addr:              *listen,
		Handler:           rendezvous.NewServer(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 1)
	go func() {
		if *certificate != "" {
			errCh <- server.ListenAndServeTLS(*certificate, *privateKey)
		} else {
			errCh <- server.ListenAndServe()
		}
	}()
	fmt.Printf("p2pstore rendezvous listening on %s\n", *listen)
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			fatal(err.Error())
		}
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			fatal(err.Error())
		}
	}
}

// loopbackAddress enforces that plaintext development mode cannot bind a LAN or
// wildcard interface.
func loopbackAddress(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// fatal prints a command-scoped error and exits nonzero.
func fatal(message string) {
	fmt.Fprintln(os.Stderr, "p2pstore-rendezvous:", message)
	os.Exit(1)
}
