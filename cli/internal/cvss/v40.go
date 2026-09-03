package cvss

import (
	"fmt"
	"math"
)

// validV40 holds the allowed values for each CVSS v4.0 base metric.
var validV40 = map[string]map[string]bool{
	"AV": {"N": true, "A": true, "L": true, "P": true},
	"AC": {"L": true, "H": true},
	"AT": {"N": true, "P": true},
	"PR": {"N": true, "L": true, "H": true},
	"UI": {"N": true, "P": true, "A": true},
	"VC": {"H": true, "L": true, "N": true},
	"VI": {"H": true, "L": true, "N": true},
	"VA": {"H": true, "L": true, "N": true},
	"SC": {"H": true, "L": true, "N": true},
	"SI": {"H": true, "L": true, "N": true},
	"SA": {"H": true, "L": true, "N": true},
}

func validateV40(name, value string) error {
	allowed, ok := validV40[name]
	if !ok {
		return fmt.Errorf("unknown CVSS 4.0 metric: %s", name)
	}
	if !allowed[value] {
		return fmt.Errorf("invalid %s value: %q", name, value)
	}
	return nil
}

// computeEQ1 determines equivalence class 1 from AV, PR, UI.
func computeEQ1(av, pr, ui string) int {
	if av == "N" && pr == "N" && ui == "N" {
		return 0
	}
	if av == "N" || pr == "N" || ui == "N" {
		return 1
	}
	return 2
}

// computeEQ2 determines equivalence class 2 from AC, AT.
func computeEQ2(ac, at string) int {
	if ac == "L" && at == "N" {
		return 0
	}
	return 1
}

// computeEQ3 determines equivalence class 3 from VC, VI, VA.
// CR, IR, AR default to H for base-only scoring.
func computeEQ3(vc, vi, va string) int {
	if vc == "H" && vi == "H" {
		return 0
	}
	if vc == "H" || vi == "H" || va == "H" {
		return 1
	}
	return 2
}

// computeEQ4 determines equivalence class 4 from SC, SI, SA.
func computeEQ4(sc, si, sa string) int {
	if sc == "H" && si == "H" {
		return 0
	}
	if sc == "H" || si == "H" || sa == "H" {
		return 1
	}
	return 2
}

// computeEQ5 returns 0 because the default Exploit Maturity is A (Attacked).
func computeEQ5() int {
	return 0
}

// computeEQ6 determines equivalence class 6.
// With defaults CR=H, IR=H, AR=H, this checks whether any vulnerable CIA is H.
func computeEQ6(vc, vi, va string) int {
	if vc == "H" || vi == "H" || va == "H" {
		return 0
	}
	return 1
}

// buildMacroVector returns the 6-digit MacroVector string.
func buildMacroVector(av, ac, at, pr, ui, vc, vi, va, sc, si, sa string) string {
	eq1 := computeEQ1(av, pr, ui)
	eq2 := computeEQ2(ac, at)
	eq3 := computeEQ3(vc, vi, va)
	eq4 := computeEQ4(sc, si, sa)
	eq5 := computeEQ5()
	eq6 := computeEQ6(vc, vi, va)
	return fmt.Sprintf("%d%d%d%d%d%d", eq1, eq2, eq3, eq4, eq5, eq6)
}

// maxEQLevel is the maximum value each EQ dimension can take.
var maxEQLevel = [6]int{2, 1, 2, 2, 2, 1}

// CalculateV40 computes a CVSS v4.0 base score from the eleven base metrics.
//
// The algorithm computes a 6-digit MacroVector from equivalence classes,
// looks up the base score from the specification's 274-entry table, then
// applies interpolation across all EQ dimensions.
//
// Parameters:
//
//	av:  Attack Vector (N, A, L, P)
//	ac:  Attack Complexity (L, H)
//	at:  Attack Requirements (N, P)
//	pr:  Privileges Required (N, L, H)
//	ui:  User Interaction (N, P, A)
//	vc:  Vulnerable System Confidentiality (H, L, N)
//	vi:  Vulnerable System Integrity (H, L, N)
//	va:  Vulnerable System Availability (H, L, N)
//	sc:  Subsequent System Confidentiality (H, L, N)
//	si:  Subsequent System Integrity (H, L, N)
//	sa:  Subsequent System Availability (H, L, N)
func CalculateV40(av, ac, at, pr, ui, vc, vi, va, sc, si, sa string) (*CvssOutput, error) {
	metrics := []struct {
		name  string
		value string
	}{
		{"AV", av}, {"AC", ac}, {"AT", at}, {"PR", pr}, {"UI", ui},
		{"VC", vc}, {"VI", vi}, {"VA", va},
		{"SC", sc}, {"SI", si}, {"SA", sa},
	}
	for _, m := range metrics {
		if err := validateV40(m.name, m.value); err != nil {
			return nil, err
		}
	}

	// If all impact metrics are None, the score is 0.0 per CVSS v4.0 spec.
	if vc == "N" && vi == "N" && va == "N" && sc == "N" && si == "N" && sa == "N" {
		vectorStr := fmt.Sprintf("CVSS:4.0/AV:%s/AC:%s/AT:%s/PR:%s/UI:%s/VC:%s/VI:%s/VA:%s/SC:%s/SI:%s/SA:%s",
			av, ac, at, pr, ui, vc, vi, va, sc, si, sa)
		return &CvssOutput{
			VectorString: vectorStr,
			BaseScore:    0.0,
			Severity:     SeverityRating(0.0),
			Metrics: map[string]string{
				"AV": av, "AC": ac, "AT": at, "PR": pr, "UI": ui,
				"VC": vc, "VI": vi, "VA": va,
				"SC": sc, "SI": si, "SA": sa,
			},
		}, nil
	}

	mv := buildMacroVector(av, ac, at, pr, ui, vc, vi, va, sc, si, sa)

	baseScore, found := macroVectorScores[mv]
	if !found {
		// MacroVector not in table means zero impact.
		baseScore = 0.0
	}

	if baseScore > 0.0 {
		baseScore = interpolate(mv, baseScore, av, ac, at, pr, ui, vc, vi, va, sc, si, sa)
	}

	vectorStr := fmt.Sprintf("CVSS:4.0/AV:%s/AC:%s/AT:%s/PR:%s/UI:%s/VC:%s/VI:%s/VA:%s/SC:%s/SI:%s/SA:%s",
		av, ac, at, pr, ui, vc, vi, va, sc, si, sa)

	return &CvssOutput{
		VectorString: vectorStr,
		BaseScore:    baseScore,
		Severity:     SeverityRating(baseScore),
		Metrics: map[string]string{
			"AV": av, "AC": ac, "AT": at, "PR": pr, "UI": ui,
			"VC": vc, "VI": vi, "VA": va,
			"SC": sc, "SI": si, "SA": sa,
		},
	}, nil
}

// interpolate adjusts the MacroVector lookup score based on severity distances
// within each equivalence class.
func interpolate(mv string, baseLookup float64, av, ac, at, pr, ui, vc, vi, va, sc, si, sa string) float64 {
	eqLevels := [6]int{
		int(mv[0] - '0'),
		int(mv[1] - '0'),
		int(mv[2] - '0'),
		int(mv[3] - '0'),
		int(mv[4] - '0'),
		int(mv[5] - '0'),
	}

	var totalAdjust float64
	var count int

	for dim := 0; dim < 6; dim++ {
		if eqLevels[dim] >= maxEQLevel[dim] {
			// Already at maximum (lowest severity) for this EQ, no lower to go.
			continue
		}

		// Build the next-lower MacroVector by incrementing this dimension.
		nextLevels := eqLevels
		nextLevels[dim]++
		nextMV := fmt.Sprintf("%d%d%d%d%d%d",
			nextLevels[0], nextLevels[1], nextLevels[2],
			nextLevels[3], nextLevels[4], nextLevels[5])

		nextScore, exists := macroVectorScores[nextMV]
		if !exists {
			// No valid next-lower vector; use 0 as the floor.
			nextScore = 0.0
		}

		availableDistance := baseLookup - nextScore

		// Compute the severity distance for this dimension.
		sevDist := severityDistance(dim, av, ac, at, pr, ui, vc, vi, va, sc, si, sa)
		maxDist := maxSeverityDistance(dim)

		if maxDist == 0 {
			continue
		}

		proportion := float64(sevDist) / float64(maxDist)
		totalAdjust += proportion * availableDistance
		count++
	}

	if count == 0 {
		return baseLookup
	}

	adjusted := baseLookup - (totalAdjust / float64(count))
	// Round to one decimal place.
	adjusted = math.Round(adjusted*10) / 10.0
	if adjusted < 0 {
		adjusted = 0.0
	}
	return adjusted
}

// metricDepth maps each metric value to a depth integer (0 = highest severity).
// The higher the depth, the lower the severity.
var metricDepth = map[string]map[string]int{
	"AV": {"N": 0, "A": 1, "L": 2, "P": 3},
	"PR": {"N": 0, "L": 1, "H": 2},
	"UI": {"N": 0, "P": 1, "A": 2},
	"AC": {"L": 0, "H": 1},
	"AT": {"N": 0, "P": 1},
	"VC": {"H": 0, "L": 1, "N": 2},
	"VI": {"H": 0, "L": 1, "N": 2},
	"VA": {"H": 0, "L": 1, "N": 2},
	"SC": {"H": 0, "L": 1, "N": 2},
	"SI": {"H": 0, "L": 1, "N": 2},
	"SA": {"H": 0, "L": 1, "N": 2},
}

// severityDistance computes how far the current metrics are from the highest
// severity vector within the given EQ dimension.  The "highest severity" means
// depth 0 for every contributing metric.
func severityDistance(dim int, av, ac, at, pr, ui, vc, vi, va, sc, si, sa string) int {
	switch dim {
	case 0: // EQ1: AV, PR, UI
		return metricDepth["AV"][av] + metricDepth["PR"][pr] + metricDepth["UI"][ui]
	case 1: // EQ2: AC, AT
		return metricDepth["AC"][ac] + metricDepth["AT"][at]
	case 2: // EQ3: VC, VI, VA
		return metricDepth["VC"][vc] + metricDepth["VI"][vi] + metricDepth["VA"][va]
	case 3: // EQ4: SC, SI, SA
		return metricDepth["SC"][sc] + metricDepth["SI"][si] + metricDepth["SA"][sa]
	case 4: // EQ5: E (default A → depth 0)
		return 0
	case 5: // EQ6: VC, VI, VA (same metrics, different EQ grouping)
		return metricDepth["VC"][vc] + metricDepth["VI"][vi] + metricDepth["VA"][va]
	}
	return 0
}

// maxSeverityDistance returns the maximum possible severity distance for a
// given EQ dimension.  This is the sum of the maximum depths of each
// contributing metric.
func maxSeverityDistance(dim int) int {
	switch dim {
	case 0: // AV(max 3) + PR(max 2) + UI(max 2)
		return 7
	case 1: // AC(max 1) + AT(max 1)
		return 2
	case 2: // VC(max 2) + VI(max 2) + VA(max 2)
		return 6
	case 3: // SC(max 2) + SI(max 2) + SA(max 2)
		return 6
	case 4: // E only (max 2, but default is A=0)
		return 2
	case 5: // VC(max 2) + VI(max 2) + VA(max 2)
		return 6
	}
	return 0
}
