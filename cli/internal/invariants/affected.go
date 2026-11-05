package invariants

import "strings"

// Affected is an invariant whose surface is in a change set.
type Affected struct {
	ID      string `json:"id"`
	Surface string `json:"surface"`
	Enforce bool   `json:"enforce"`
	Path    string `json:"path"`
}

// AffectedBySurfaces returns, in file order, every invariant whose surface
// is one of the given surface ids: the invariants a change to those
// surfaces' files is covered by.
func AffectedBySurfaces(invs []Invariant, surfaces []string) []Affected {
	changed := make(map[string]bool, len(surfaces))
	for _, id := range surfaces {
		changed[strings.TrimSpace(id)] = true
	}
	affected := []Affected{}
	for _, inv := range invs {
		if inv.Surface != "" && changed[inv.Surface] {
			affected = append(affected, Affected{ID: inv.ID, Surface: inv.Surface, Enforce: inv.Enforce, Path: inv.Path})
		}
	}
	return affected
}
