package enums

import (
	"fmt"
	"sort"
	"strings"
)

var ValidVulnTypes = map[string]bool{
	"sqli": true, "xss": true, "ssrf": true, "csv_injection": true,
	"cmdi": true, "lfi": true, "ssti": true, "deserialization": true,
	"xxe": true, "idor": true, "authz": true, "redirect": true, "csrf": true,
	"nosql": true, "auth_bypass": true,
	"prototype_pollution": true, "graphql": true, "jwt": true,
	"cors": true, "race_condition": true,
	"cache_poisoning": true,
	"ldap":            true, "xpath": true, "header_injection": true, "file_upload": true,
	"clickjacking": true,
	// Cloud security vuln types (no payloads — used for compliance mapping and evidence logging)
	"cloud_iam": true, "cloud_storage": true, "cloud_network": true,
	"cloud_compute": true, "cloud_logging": true, "cloud_k8s": true,
	"cloud_secrets": true, "iac_misconfig": true,
	// OWASP A10:2025 — Mishandling of Exceptional Conditions (no payloads — compliance mapping and evidence logging)
	"error_handling": true,
	// OWASP API Security Top 10 2023
	"property_authz": true, "api_inventory": true, "mass_assignment": true,
	// Rate and size limits — verification probes only (no payloads)
	"rate_limit": true, "limits": true,
	// One analyst-constructed scoped request — verification probe only (no payloads)
	"request": true,
	// Transport-level — compliance mapping and verification probes (no payloads)
	"websocket": true, "grpc": true,
}

var ValidTechniques = map[string]bool{
	"blind_time": true, "blind_boolean": true, "error_based": true, "union": true,
	"dns": true, "oob": true,
	"metadata_access": true, "internal_service": true, "protocol_smuggling": true,
	"port_scan": true, "cross_tenant": true,
	"formula_injection": true, "open_redirect": true, "path_traversal": true,
	"server_action": true, "webhook_spoof": true,
	"rls_isolation": true,
	// XSS techniques
	"reflected": true, "stored": true, "dom": true, "polyglot": true,
	// Command injection techniques
	"command_injection": true, "command_chaining": true, "argument_injection": true,
	// NoSQL injection techniques
	"nosql_injection": true, "operator_injection": true, "js_injection": true, "where_time": true,
	// LFI techniques
	"directory_traversal": true, "null_byte": true, "wrapper": true,
	// SSTI techniques
	"sandbox_escape": true, "expression_eval": true,
	// XXE techniques
	"xxe_file_read": true, "xxe_ssrf": true, "xxe_oob": true, "xxe_dos": true,
	// Redirect techniques
	"open_redirect_param": true, "open_redirect_path": true,
	// Timing and out-of-band techniques
	"time_based": true, "dns_oob": true,
	// Auth bypass techniques
	"jwt_manipulation": true, "default_credential": true, "forced_browsing": true,
	"auth_control": true, "session_fixation": true,
	// IDOR/BOLA techniques
	"idor_numeric": true, "idor_uuid": true, "idor_path": true, "bola": true, "role_differential": true,
	// CSRF techniques
	"form_auto_submit": true, "xhr_cross_origin": true, "fetch_cross_origin": true, "image_tag": true, "origin_validation": true,
	// Prototype pollution techniques
	"proto_assignment": true, "constructor_pollution": true, "json_merge": true,
	// GraphQL techniques
	"introspection": true, "batch_query": true, "nested_query_dos": true, "field_suggestion": true, "alias_dos": true,
	// JWT techniques
	"alg_none": true, "alg_confusion": true, "kid_injection": true, "jwk_injection": true, "jku_spoofing": true,
	// CORS techniques
	"origin_reflection": true, "null_origin": true, "subdomain_wildcard": true, "credential_leak": true,
	// Race condition techniques
	"toctou": true, "parallel_request": true, "double_spend": true,
	// Cache poisoning techniques
	"unkeyed_header": true, "unkeyed_cookie": true, "fat_get": true,
	// Auth verify techniques
	"no_token": true, "expired_token": true, "method_override": true,
	// LDAP injection techniques
	"ldap_filter_injection": true, "ldap_blind_boolean": true, "ldap_blind_error": true,
	// XPath injection techniques
	"xpath_injection": true, "xpath_blind_boolean": true, "xpath_blind_error": true,
	// Header injection techniques
	"crlf_injection": true, "response_splitting": true, "email_header_injection": true,
	// File upload techniques
	"extension_bypass": true, "mime_bypass": true, "polyglot_file": true,
	"zip_path_traversal": true, "content_type_mismatch": true,
	// Clickjacking technique
	"frame_header_check": true,
	// Rate and size limit measurement techniques
	"rate_limit_burst": true, "account_enumeration": true,
	"scoped_request": true,
	"pagination":     true, "upload_size": true, "response_size": true,
	// DOM clobbering (XSS variant)
	"dom_clobbering": true,
	// WebSocket techniques
	"ws_injection": true, "ws_hijack": true, "ws_origin_check": true,
	// gRPC techniques
	"grpc_reflection": true, "grpc_plaintext": true,
	// Mass assignment technique
	"mass_assignment": true,
}

var ValidDBEngines = map[string]bool{
	"postgres": true, "mysql": true, "mssql": true, "sqlite": true, "oracle": true,
}

var ValidRuntimes = map[string]bool{
	"node": true, "jvm": true, "python": true, "php": true,
	"dotnet": true, "ruby": true, "go": true,
}

var ValidInjectionSurfaces = map[string]bool{
	"query": true, "path": true, "header": true, "cookie": true,
	"json_body": true, "form_body": true,
	"xml_body": true, "file_upload": true,
	"websocket": true, "graphql_query": true,
	"grpc_unary": true,
}

var ValidEncodings = map[string]bool{
	"raw": true, "url": true, "double_url": true,
	"unicode": true, "hex": true, "base64": true,
	"html_entity": true, "js_escape": true, "null_byte": true,
}

var ValidStringBoundaries = map[string]bool{
	"single_quote": true, "double_quote": true, "unquoted": true, "numeric": true,
}

var ValidEvidenceTypes = map[string]bool{
	"timing": true, "boolean_diff": true, "error": true, "content_match": true,
	"dns_hit": true, "oob": true,
	"status_diff": true, "header_match": true, "redirect": true,
	"response_diff": true, "callback_hit": true, "dom_execution": true,
}

// ValidateFilter checks all non-empty filter fields against known enum values.
func ValidateFilter(vulnType, dbEngine, runtime, technique, surface, encoding, boundary string) error {
	var errs []string

	if vulnType != "" && !ValidVulnTypes[vulnType] {
		errs = append(errs, fmt.Sprintf("invalid vuln_type %q — valid: %s", vulnType, SortedKeys(ValidVulnTypes)))
	}
	if dbEngine != "" && !ValidDBEngines[dbEngine] {
		errs = append(errs, fmt.Sprintf("invalid db %q — valid: %s", dbEngine, SortedKeys(ValidDBEngines)))
	}
	if runtime != "" && !ValidRuntimes[runtime] {
		errs = append(errs, fmt.Sprintf("invalid runtime %q — valid: %s", runtime, SortedKeys(ValidRuntimes)))
	}
	if technique != "" && !ValidTechniques[technique] {
		errs = append(errs, fmt.Sprintf("invalid technique %q — valid: %s", technique, SortedKeys(ValidTechniques)))
	}
	if surface != "" && !ValidInjectionSurfaces[surface] {
		errs = append(errs, fmt.Sprintf("invalid surface %q — valid: %s", surface, SortedKeys(ValidInjectionSurfaces)))
	}
	if encoding != "" && !ValidEncodings[encoding] {
		errs = append(errs, fmt.Sprintf("invalid encoding %q — valid: %s", encoding, SortedKeys(ValidEncodings)))
	}
	if boundary != "" && !ValidStringBoundaries[boundary] {
		errs = append(errs, fmt.Sprintf("invalid boundary %q — valid: %s", boundary, SortedKeys(ValidStringBoundaries)))
	}

	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "\n"))
	}
	return nil
}

// ValidateSeedPayload checks all enum fields of a seed payload entry.
func ValidateSeedPayload(vulnType, dbEngine, runtime, technique, injectionSurface, encoding, stringBoundary, evidenceType, file string, index int) error {
	var errs []string

	if vulnType != "" && !ValidVulnTypes[vulnType] {
		errs = append(errs, fmt.Sprintf("vuln_type %q", vulnType))
	}
	if dbEngine != "" && !ValidDBEngines[dbEngine] {
		errs = append(errs, fmt.Sprintf("db_engine %q", dbEngine))
	}
	if runtime != "" && !ValidRuntimes[runtime] {
		errs = append(errs, fmt.Sprintf("runtime %q", runtime))
	}
	if technique != "" && !ValidTechniques[technique] {
		errs = append(errs, fmt.Sprintf("technique %q", technique))
	}
	if injectionSurface != "" && !ValidInjectionSurfaces[injectionSurface] {
		errs = append(errs, fmt.Sprintf("injection_surface %q", injectionSurface))
	}
	if encoding != "" && !ValidEncodings[encoding] {
		errs = append(errs, fmt.Sprintf("encoding %q", encoding))
	}
	if stringBoundary != "" && !ValidStringBoundaries[stringBoundary] {
		errs = append(errs, fmt.Sprintf("string_boundary %q", stringBoundary))
	}
	if evidenceType != "" && !ValidEvidenceTypes[evidenceType] {
		errs = append(errs, fmt.Sprintf("evidence_type %q", evidenceType))
	}

	if len(errs) > 0 {
		return fmt.Errorf("%s: payload %d: invalid enum values: %s", file, index, strings.Join(errs, ", "))
	}
	return nil
}

func SortedKeys(m map[string]bool) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}
