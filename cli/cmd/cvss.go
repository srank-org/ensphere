package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/srank-org/ensphere/internal/cvss"
)

var (
	cvssAV string
	cvssAC string
	cvssPR string
	cvssUI string
	cvssAT string
	cvssVC string
	cvssVI string
	cvssVA string
	cvssSC string
	cvssSI string
	cvssSA string
)

var cvssCmd = &cobra.Command{
	Use:   "cvss",
	Short: "Calculate a CVSS 4.0 base score",
	Long: `Calculate a CVSS 4.0 base score from metric values.

Outputs JSON with the vector string, numeric score, severity rating, and
supplied metrics.

Examples:
  ensphere cvss --av N --ac L --at N --pr N --ui N \
    --vc H --vi H --va H --sc H --si H --sa H`,
	RunE: runCvss,
}

func init() {
	cvssCmd.Flags().StringVar(&cvssAV, "av", "", "Attack Vector (N/A/L/P)")
	cvssCmd.Flags().StringVar(&cvssAC, "ac", "", "Attack Complexity (L/H)")
	cvssCmd.Flags().StringVar(&cvssPR, "pr", "", "Privileges Required (N/L/H)")
	cvssCmd.Flags().StringVar(&cvssUI, "ui", "", "User Interaction")
	cvssCmd.Flags().StringVar(&cvssAT, "at", "", "Attack Requirements (N/P)")
	cvssCmd.Flags().StringVar(&cvssVC, "vc", "", "Vulnerable Confidentiality (H/L/N)")
	cvssCmd.Flags().StringVar(&cvssVI, "vi", "", "Vulnerable Integrity (H/L/N)")
	cvssCmd.Flags().StringVar(&cvssVA, "va", "", "Vulnerable Availability (H/L/N)")
	cvssCmd.Flags().StringVar(&cvssSC, "sc", "", "Subsequent Confidentiality (H/L/N)")
	cvssCmd.Flags().StringVar(&cvssSI, "si", "", "Subsequent Integrity (H/L/N)")
	cvssCmd.Flags().StringVar(&cvssSA, "sa", "", "Subsequent Availability (H/L/N)")

	rootCmd.AddCommand(cvssCmd)
}

func runCvss(cmd *cobra.Command, args []string) error {
	if err := requireFlags("CVSS 4.0", map[string]string{
		"--av": cvssAV, "--ac": cvssAC, "--at": cvssAT,
		"--pr": cvssPR, "--ui": cvssUI,
		"--vc": cvssVC, "--vi": cvssVI, "--va": cvssVA,
		"--sc": cvssSC, "--si": cvssSI, "--sa": cvssSA,
	}); err != nil {
		return err
	}

	result, err := cvss.CalculateV40(
		strings.ToUpper(cvssAV), strings.ToUpper(cvssAC), strings.ToUpper(cvssAT),
		strings.ToUpper(cvssPR), strings.ToUpper(cvssUI),
		strings.ToUpper(cvssVC), strings.ToUpper(cvssVI), strings.ToUpper(cvssVA),
		strings.ToUpper(cvssSC), strings.ToUpper(cvssSI), strings.ToUpper(cvssSA),
	)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

// requireFlags checks that every flag in the map has a non-empty value.
func requireFlags(label string, flags map[string]string) error {
	var missing []string
	for name, val := range flags {
		if strings.TrimSpace(val) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%s requires flags: %s", label, strings.Join(missing, ", "))
	}
	return nil
}
