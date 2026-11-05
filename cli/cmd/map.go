package cmd

import (
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/srank-org/ensphere/internal/invariants"
	"github.com/srank-org/ensphere/internal/runner"
	"github.com/srank-org/ensphere/internal/sysmap"
)

var (
	mapSourcePath string
	mapFile       string
	mapSince      string
)

var mapCmd = &cobra.Command{
	Use:   "map",
	Short: "Validate the system map and list the surfaces changed since a commit",
	Long: `The system map is <source-path>/.ensphere/surfaces.yaml, the committed
inventory of the target's surfaces: the source files that implement each one
and the sessions that own its checks. The agent writes it during recon; the
CLI validates it and joins git's change set to it. Nothing here judges a
surface.`,
}

var mapValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate the system map against the source tree",
	Long: `Check the system map's structure, vocabulary, and that every file a surface
claims exists under --source-path. Exits 1 when any issue is an error and 3
when the map cannot be read or parsed.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		validation, _, err := validateMapFile()
		if err != nil {
			return exitRunError(err)
		}
		return exitOnMapErrors(validation)
	},
}

var mapChangedCmd = &cobra.Command{
	Use:   "changed",
	Short: "List the surfaces whose files changed since a commit",
	Long: `Validate the map, then compare the working tree with --since (default: the
map's reconciled_at) using git. Uncommitted and untracked files count. Prints
the changed files, the surfaces that claim them, changed files no surface
claims, claimed files that no longer exist, and the sessions those surfaces
name. Exits 1 with the validation output when the map has errors and 3 when
the map or git fails.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		validation, m, err := validateMapFile()
		if err != nil {
			return exitRunError(err)
		}
		if !validation.Valid {
			return exitOnMapErrors(validation)
		}
		changes, err := sysmap.Changed(m, mapSourcePath, mapSince)
		if err != nil {
			return exitRunError(err)
		}
		return encodeRunJSON(changeSetWithInvariants(changes, mapSourcePath))
	},
}

// changeSetOutput is ensphere map changed's output: the change set plus the
// invariants whose surface is in it, when the source tree holds any.
type changeSetOutput struct {
	*sysmap.ChangeSet
	InvariantsAffected []invariants.Affected `json:"invariants_affected"`
}

func changeSetWithInvariants(changes *sysmap.ChangeSet, sourcePath string) changeSetOutput {
	out := changeSetOutput{ChangeSet: changes, InvariantsAffected: []invariants.Affected{}}
	dir := filepath.Join(sourcePath, invariants.DefaultDir)
	if _, err := os.Stat(dir); err != nil {
		return out
	}
	invs, _, err := invariants.Load(dir)
	if err != nil {
		return out
	}
	ids := make([]string, 0, len(changes.ChangedSurfaces))
	for _, surface := range changes.ChangedSurfaces {
		ids = append(ids, surface.ID)
	}
	out.InvariantsAffected = invariants.AffectedBySurfaces(invs, ids)
	return out
}

func validateMapFile() (*sysmap.Validation, *sysmap.Map, error) {
	path := mapFile
	if path == "" {
		path = sysmap.Path(mapSourcePath)
	}
	return sysmap.ValidateFile(path, mapSourcePath, runner.CheckSessionIDs())
}

func exitOnMapErrors(validation *sysmap.Validation) error {
	if err := encodeRunJSON(validation); err != nil {
		return err
	}
	if !validation.Valid {
		osExit(1)
	}
	return nil
}

func init() {
	mapCmd.PersistentFlags().StringVar(&mapSourcePath, "source-path", ".", "Path to the source tree the map describes")
	mapCmd.PersistentFlags().StringVar(&mapFile, "map", "", "System map path (default: <source-path>/.ensphere/surfaces.yaml)")
	mapChangedCmd.Flags().StringVar(&mapSince, "since", "", "Git commit or ref to compare the working tree with (default: the map's reconciled_at)")

	mapCmd.AddCommand(mapValidateCmd, mapChangedCmd)
	rootCmd.AddCommand(mapCmd)
}
