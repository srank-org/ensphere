package cmd

import (
	"github.com/spf13/cobra"

	"github.com/srank-org/ensphere/internal/verify"
)

var (
	fuURL       string
	fuField     string
	fuFilename  string
	fuContent   string
	fuMIMEType  string
	fuVerifyURL string
	fuTechnique string
	fuMethod    string
	fuProbe     probeFlags
)

var verifyFileUploadCmd = &cobra.Command{
	Use:   "fileupload",
	Short: "Verify file upload vulnerability",
	Long: `Verify file upload vulnerabilities with extension, MIME, or content-based bypass probes.

Techniques:
  extension_bypass       Upload file with double/bypassed extension (risk 3)
  mime_bypass            Upload file with mismatched MIME type (risk 3)
  content_type_mismatch  Send Content-Type that doesn't match file content (risk 3)
  polyglot_file          Upload polyglot file that is valid in multiple formats (risk 4)
  zip_path_traversal     Upload ZIP with path traversal in filename (risk 4)

Examples:
  ensphere verify fileupload --url "http://target/upload" --filename "shell.php.jpg" --technique extension_bypass --in-scope "*.target.com"
  ensphere verify fileupload --url "http://target/upload" --filename "test.php" --mime-type "image/jpeg" --technique mime_bypass --in-scope "*.target.com"
  ensphere verify fileupload --url "http://target/upload" --filename "poly.php" --content "GIF89a<?php ?>" --technique polyglot_file --in-scope "*.target.com" --max-risk 4
  ensphere verify fileupload --url "http://target/upload" --filename "shell.php" --technique extension_bypass --verify-url "http://target/uploads/shell.php" --in-scope "*.target.com"`,
	RunE: runVerifyFileUpload,
}

func init() {
	verifyFileUploadCmd.Flags().StringVar(&fuURL, "url", "", "Target upload URL (required)")
	verifyFileUploadCmd.Flags().StringVar(&fuField, "field", "file", "Form field name for the file")
	verifyFileUploadCmd.Flags().StringVar(&fuFilename, "filename", "", "Test filename to upload (required)")
	verifyFileUploadCmd.Flags().StringVar(&fuContent, "content", "ensphere_upload_test", "File content to upload")
	verifyFileUploadCmd.Flags().StringVar(&fuMIMEType, "mime-type", "application/octet-stream", "Content-Type for the file part")
	verifyFileUploadCmd.Flags().StringVar(&fuVerifyURL, "verify-url", "", "URL to GET after upload to check accessibility")
	verifyFileUploadCmd.Flags().StringVar(&fuTechnique, "technique", "", "Technique: extension_bypass, mime_bypass, content_type_mismatch, polyglot_file, zip_path_traversal (required)")
	verifyFileUploadCmd.Flags().StringVar(&fuMethod, "method", "POST", "HTTP method")

	_ = verifyFileUploadCmd.MarkFlagRequired("url")
	_ = verifyFileUploadCmd.MarkFlagRequired("filename")
	_ = verifyFileUploadCmd.MarkFlagRequired("technique")

	addProbeFlags(verifyFileUploadCmd, &fuProbe)

	verifyCmd.AddCommand(verifyFileUploadCmd)
}

func runVerifyFileUpload(cmd *cobra.Command, args []string) error {

	cfg := verify.FileUploadConfig{
		URL:         fuURL,
		FieldName:   fuField,
		Filename:    fuFilename,
		Content:     fuContent,
		MIMEType:    fuMIMEType,
		VerifyURL:   fuVerifyURL,
		Technique:   fuTechnique,
		Method:      fuMethod,
		ProbeConfig: buildProbeConfig(&fuProbe),
	}

	return runVerify(func() (*verify.ProbeResult, error) {
		return verify.VerifyFileUpload(cfg)
	})
}
