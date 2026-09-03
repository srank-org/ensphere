package openapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// httpMethods lists the HTTP methods recognized in OpenAPI path items.
var httpMethods = []string{"get", "post", "put", "delete", "patch", "options", "head"}

// Parse reads an OpenAPI spec from a file path and returns structured data.
func Parse(filePath string) (*Spec, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	return parseSpec(data)
}

// ParseURL fetches an OpenAPI spec from a URL and returns structured data.
func ParseURL(url string, timeoutSec int) (*Spec, error) {
	client := &http.Client{Timeout: time.Duration(timeoutSec) * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch url: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("fetch url: server returned %d", resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	return parseSpec(data)
}

// parseSpec parses raw bytes (YAML or JSON) into a Spec.
func parseSpec(data []byte) (*Spec, error) {
	var raw map[string]interface{}

	// Try YAML first (YAML is a superset of JSON, so this handles both).
	if err := yaml.Unmarshal(data, &raw); err != nil {
		// Fall back to JSON.
		if jerr := json.Unmarshal(data, &raw); jerr != nil {
			return nil, fmt.Errorf("parse spec: not valid YAML (%v) or JSON (%v)", err, jerr)
		}
	}

	spec := &Spec{}

	info := getMap(raw, "info")
	spec.Title = getStr(info, "title")
	spec.Version = getStr(info, "version")
	spec.Description = getStr(info, "description")

	for _, s := range getSlice(raw, "servers") {
		sm, ok := s.(map[string]interface{})
		if !ok {
			continue
		}
		spec.Servers = append(spec.Servers, Server{
			URL:         getStr(sm, "url"),
			Description: getStr(sm, "description"),
		})
	}

	topSecurity := getSlice(raw, "security")
	hasTopSecurity := len(topSecurity) > 0

	paths := getMap(raw, "paths")
	uniquePaths := map[string]bool{}
	totalOps := 0

	for path, pathVal := range paths {
		pathItem, ok := pathVal.(map[string]interface{})
		if !ok {
			continue
		}
		uniquePaths[path] = true

		pathParams := extractParameters(getSlice(pathItem, "parameters"))

		for _, method := range httpMethods {
			opVal, exists := pathItem[method]
			if !exists {
				continue
			}
			op, ok := opVal.(map[string]interface{})
			if !ok {
				continue
			}
			totalOps++

			ep := Endpoint{
				Method:      strings.ToUpper(method),
				Path:        path,
				OperationID: getStr(op, "operationId"),
				Summary:     getStr(op, "summary"),
				Deprecated:  getBool(op, "deprecated"),
			}

			for _, t := range getSlice(op, "tags") {
				if ts, ok := t.(string); ok {
					ep.Tags = append(ep.Tags, ts)
				}
			}

			opParams := extractParameters(getSlice(op, "parameters"))
			ep.Parameters = mergeParameters(pathParams, opParams)

			if rb := getMap(op, "requestBody"); rb != nil {
				body := &RequestBody{
					Required: getBool(rb, "required"),
				}
				if content := getMap(rb, "content"); content != nil {
					for ct := range content {
						body.ContentTypes = append(body.ContentTypes, ct)
					}
					sort.Strings(body.ContentTypes)
				}
				ep.RequestBody = body
			}

			ep.AuthRequired = determineAuthRequired(op, hasTopSecurity)

			spec.Endpoints = append(spec.Endpoints, ep)
		}
	}

	spec.TotalPaths = len(uniquePaths)
	spec.TotalOps = totalOps

	sort.Slice(spec.Endpoints, func(i, j int) bool {
		if spec.Endpoints[i].Path != spec.Endpoints[j].Path {
			return spec.Endpoints[i].Path < spec.Endpoints[j].Path
		}
		return spec.Endpoints[i].Method < spec.Endpoints[j].Method
	})

	return spec, nil
}

// determineAuthRequired checks whether an operation requires authentication.
// If the operation has an explicit "security" key, use it: an empty array
// means no auth, a non-empty array means auth required. If there is no
// operation-level security, fall back to top-level security.
func determineAuthRequired(op map[string]interface{}, hasTopSecurity bool) bool {
	if secVal, exists := op["security"]; exists {
		if secSlice, ok := secVal.([]interface{}); ok {
			return len(secSlice) > 0
		}
		return false
	}
	return hasTopSecurity
}

// extractParameters converts a raw parameter slice to typed Parameters.
func extractParameters(raw []interface{}) []Parameter {
	var params []Parameter
	for _, p := range raw {
		pm, ok := p.(map[string]interface{})
		if !ok {
			continue
		}
		param := Parameter{
			Name:     getStr(pm, "name"),
			In:       getStr(pm, "in"),
			Required: getBool(pm, "required"),
		}
		if schema := getMap(pm, "schema"); schema != nil {
			param.Type = getStr(schema, "type")
		}
		params = append(params, param)
	}
	return params
}

// mergeParameters merges path-level and operation-level parameters.
// Operation-level parameters override path-level ones with the same name+in.
func mergeParameters(pathParams, opParams []Parameter) []Parameter {
	if len(pathParams) == 0 {
		return opParams
	}
	if len(opParams) == 0 {
		return pathParams
	}

	// Build set of operation param keys.
	opKeys := map[string]bool{}
	for _, p := range opParams {
		opKeys[p.Name+"|"+p.In] = true
	}

	// Start with operation params, add path params not overridden.
	merged := make([]Parameter, len(opParams))
	copy(merged, opParams)
	for _, p := range pathParams {
		if !opKeys[p.Name+"|"+p.In] {
			merged = append(merged, p)
		}
	}
	return merged
}

// getStr safely extracts a string from a map.
func getStr(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

// getBool safely extracts a bool from a map.
func getBool(m map[string]interface{}, key string) bool {
	if m == nil {
		return false
	}
	v, ok := m[key]
	if !ok {
		return false
	}
	b, ok := v.(bool)
	if !ok {
		return false
	}
	return b
}

// getMap safely extracts a sub-map from a map.
func getMap(m map[string]interface{}, key string) map[string]interface{} {
	if m == nil {
		return nil
	}
	v, ok := m[key]
	if !ok {
		return nil
	}
	sub, ok := v.(map[string]interface{})
	if !ok {
		return nil
	}
	return sub
}

// getSlice safely extracts a slice from a map.
func getSlice(m map[string]interface{}, key string) []interface{} {
	if m == nil {
		return nil
	}
	v, ok := m[key]
	if !ok {
		return nil
	}
	s, ok := v.([]interface{})
	if !ok {
		return nil
	}
	return s
}
