package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/srank/ensphere/internal/callback"
	"github.com/srank/ensphere/internal/evidence"
)

var (
	cbPort        int
	cbWait        int
	cbExternalURL string
	cbEvidence    string
)

var callbackCmd = &cobra.Command{
	Use:   "callback",
	Short: "Start an OOB callback listener",
	Long: `Start an HTTP callback server to detect out-of-band interactions.

Listens for inbound HTTP requests and records them as evidence. Use with blind SSRF,
blind XXE, or blind SSTI probes that trigger outbound connections from the target.

The server generates a unique token. Callbacks arrive at /cb/<token>.

Examples:
  ensphere callback --port 8888 --wait 30 --external-url "https://abc.ngrok.app"
  ensphere callback --port 8888 --external-url "https://abc.ngrok.app" --evidence ./evidence.jsonl`,
	RunE: runCallback,
}

func init() {
	callbackCmd.Flags().IntVar(&cbPort, "port", 8888, "Listen port")
	callbackCmd.Flags().IntVar(&cbWait, "wait", 0, "Wait N seconds for callbacks (0 = run until SIGINT)")
	callbackCmd.Flags().StringVar(&cbExternalURL, "external-url", "", "External URL (e.g., ngrok URL)")
	callbackCmd.Flags().StringVar(&cbEvidence, "evidence", "./evidence.jsonl", "Evidence file path")

	rootCmd.AddCommand(callbackCmd)
}

func runCallback(cmd *cobra.Command, args []string) error {
	cfg := callback.CallbackConfig{
		Port:        cbPort,
		WaitSec:     cbWait,
		ExternalURL: cbExternalURL,
		Evidence:    cbEvidence,
	}

	srv := callback.NewServer(cfg)

	fmt.Fprintf(os.Stderr, "[CALLBACK] token=%s\n", srv.Token())
	fmt.Fprintf(os.Stderr, "[CALLBACK] listening on 127.0.0.1:%d\n", cbPort)
	if cbExternalURL != "" {
		fmt.Fprintf(os.Stderr, "[CALLBACK] external: %s/cb/%s\n", cbExternalURL, srv.Token())
	}
	fmt.Fprintf(os.Stderr, "[CALLBACK] callback path: /cb/%s\n", srv.Token())
	if cbWait > 0 {
		fmt.Fprintf(os.Stderr, "[CALLBACK] waiting %ds for callbacks...\n", cbWait)
	} else {
		fmt.Fprintf(os.Stderr, "[CALLBACK] running until SIGINT (Ctrl+C)...\n")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle SIGINT for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	result, err := srv.Start(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "callback error: %s\n", err)
		os.Exit(3)
	}

	if cfg.Evidence != "" && result.TotalReceived > 0 {
		ew, ewErr := evidence.NewWriter(cfg.Evidence)
		if ewErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not open evidence file: %v\n", ewErr)
		} else {
			defer ew.Close()
			for _, cb := range result.Callbacks {
				entry := evidence.NewEntry("callback", "oob", cb.Path, "", 200,
					fmt.Sprintf("%dms", cb.ElapsedMs), evidence.ResultCallback,
					fmt.Sprintf("stage=received source=%s method=%s body_len=%d", cb.SourceIP, cb.Method, cb.BodyLength))
				_ = ew.Write(entry)
			}
		}
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		fmt.Fprintf(os.Stderr, "encode error: %s\n", err)
		os.Exit(3)
	}
	return nil
}
