package cmd

import (
	"github.com/spf13/cobra"

	"github.com/srank-org/ensphere/internal/verify"
)

var (
	wsURL       string
	wsTechnique string
	wsPayload   string
	wsTLSVerify bool
	wsProbe     probeFlags
)

var verifyWebSocketCmd = &cobra.Command{
	Use:   "websocket",
	Short: "Verify WebSocket security",
	Long: `Verify WebSocket security via raw TCP handshake and frame analysis.

Techniques:
  ws_injection    Send payload via WebSocket text frame after upgrade
  ws_hijack       Attempt upgrade with evil origin
  ws_origin_check Three sub-probes: no origin, null origin, evil origin

Examples:
  ensphere verify websocket --url "ws://target/ws" --technique ws_injection --payload "<script>alert(1)</script>" --in-scope "*.target.com"
  ensphere verify websocket --url "ws://target/ws" --technique ws_origin_check --in-scope "*.target.com"`,
	RunE: runVerifyWebSocket,
}

func init() {
	verifyWebSocketCmd.Flags().StringVar(&wsURL, "url", "", "Target WebSocket URL (required)")
	verifyWebSocketCmd.Flags().StringVar(&wsTechnique, "technique", "", "Technique: ws_injection, ws_hijack, ws_origin_check (required)")
	verifyWebSocketCmd.Flags().StringVar(&wsPayload, "payload", "", "Payload to send as WebSocket text frame")
	verifyWebSocketCmd.Flags().BoolVar(&wsTLSVerify, "tls-verify", true, "Verify the server TLS certificate")

	_ = verifyWebSocketCmd.MarkFlagRequired("url")
	_ = verifyWebSocketCmd.MarkFlagRequired("technique")

	addProbeFlags(verifyWebSocketCmd, &wsProbe)

	verifyCmd.AddCommand(verifyWebSocketCmd)
}

func runVerifyWebSocket(cmd *cobra.Command, args []string) error {

	cfg := verify.WebSocketConfig{
		URL:         wsURL,
		Technique:   wsTechnique,
		Payload:     wsPayload,
		TLSVerify:   wsTLSVerify,
		ProbeConfig: buildProbeConfig(&wsProbe),
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifyWebSocket(cfg)
	})
}
