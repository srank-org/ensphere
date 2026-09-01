package payloads

import "sort"

// Query filters the store's payloads and returns ranked results with tags.
//
// It reproduces the semantics of the former SQLite query exactly:
//   - vuln_type is a required exact match.
//   - db_engine, runtime, content_type and string_boundary are nullable
//     "broadening" filters: a set filter matches rows whose value equals it OR
//     whose value is absent (engine-agnostic rows are always included).
//   - technique, injection_surface and encoding are exact filters.
//   - max_risk (when > 0) keeps rows with risk <= max_risk.
//   - tag (when set) keeps rows carrying that tag.
//
// Results are ordered by broadening rank ASC (exact matches before absent-value
// fallbacks), then risk ASC, then id ASC. Payload IDs are unique content
// hashes, so id is a fully deterministic final tiebreaker and no true ties
// remain — the ordering matches the SQLite `ORDER BY rank, risk, id`.
func (s *Store) Query(f PayloadFilter) *QueryOutput {
	limit := f.Limit
	if limit <= 0 {
		limit = 20
	}

	type ranked struct {
		p    Payload
		rank int
	}
	var matched []ranked

	for _, p := range s.payloads {
		if p.VulnType != f.VulnType {
			continue
		}

		rank := 0
		if !nullableMatch(deref(p.DBEngine), f.DBEngine, &rank) {
			continue
		}
		if !nullableMatch(deref(p.Runtime), f.Runtime, &rank) {
			continue
		}
		if f.Technique != "" && p.Technique != f.Technique {
			continue
		}
		if f.Surface != "" && p.InjectionSurface != f.Surface {
			continue
		}
		if !nullableMatch(deref(p.ContentType), f.ContentType, &rank) {
			continue
		}
		if f.Encoding != "" && p.Encoding != f.Encoding {
			continue
		}
		if !nullableMatch(deref(p.StringBoundary), f.Boundary, &rank) {
			continue
		}
		if f.MaxRisk > 0 && p.Risk > f.MaxRisk {
			continue
		}
		if f.Tag != "" && !hasTag(p.Tags, f.Tag) {
			continue
		}

		matched = append(matched, ranked{p: p, rank: rank})
	}

	sort.Slice(matched, func(i, j int) bool {
		a, b := matched[i], matched[j]
		if a.rank != b.rank {
			return a.rank < b.rank
		}
		if a.p.Risk != b.p.Risk {
			return a.p.Risk < b.p.Risk
		}
		return a.p.ID < b.p.ID
	})

	if len(matched) > limit {
		matched = matched[:limit]
	}

	results := make([]PayloadResult, 0, len(matched))
	for _, m := range matched {
		p := m.p
		placeholders := p.Placeholders
		if placeholders == nil {
			placeholders = []string{}
		}
		tags := p.Tags
		if tags == nil {
			tags = []string{}
		}
		results = append(results, PayloadResult{
			ID:               p.ID,
			Payload:          p.Payload,
			Technique:        p.Technique,
			InjectionSurface: p.InjectionSurface,
			Encoding:         p.Encoding,
			StringBoundary:   p.StringBoundary,
			EvidenceType:     p.EvidenceType,
			Risk:             p.Risk,
			Placeholders:     placeholders,
			Notes:            p.Notes,
			Source:           p.Source,
			Tags:             tags,
		})
	}

	echoedQuery := map[string]any{
		"vuln_type": f.VulnType,
	}
	if f.DBEngine != "" {
		echoedQuery["db_engine"] = f.DBEngine
	}
	if f.Runtime != "" {
		echoedQuery["runtime"] = f.Runtime
	}
	if f.Technique != "" {
		echoedQuery["technique"] = f.Technique
	}
	if f.Surface != "" {
		echoedQuery["injection_surface"] = f.Surface
	}
	if f.ContentType != "" {
		echoedQuery["content_type"] = f.ContentType
	}
	if f.Encoding != "" {
		echoedQuery["encoding"] = f.Encoding
	}
	if f.Boundary != "" {
		echoedQuery["string_boundary"] = f.Boundary
	}
	if f.Tag != "" {
		echoedQuery["tag"] = f.Tag
	}
	if f.MaxRisk > 0 {
		echoedQuery["max_risk"] = f.MaxRisk
	}
	echoedQuery["limit"] = limit

	return &QueryOutput{
		Query:   echoedQuery,
		Count:   len(results),
		Results: results,
	}
}

// nullableMatch reproduces `(col = value OR col IS NULL)` plus the broadening
// rank `CASE WHEN col = value THEN 0 ELSE 1 END`. An unset filter always
// matches and adds no rank; a set filter matches an equal value (rank +0) or an
// absent value (rank +1) and excludes any other value.
func nullableMatch(colVal, filterVal string, rank *int) bool {
	if filterVal == "" {
		return true
	}
	if colVal == filterVal {
		return true
	}
	if colVal == "" {
		*rank++
		return true
	}
	return false
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func hasTag(tags []string, tag string) bool {
	for _, t := range tags {
		if t == tag {
			return true
		}
	}
	return false
}
