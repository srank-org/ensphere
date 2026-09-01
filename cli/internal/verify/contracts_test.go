package verify

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/srank/ensphere/internal/enums"
)

// testJWT is a valid 3-part JWT for contract tests requiring JWT parsing.
const testJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

type probeContract struct {
	name             string
	risk             int
	callOutOfScope   func() (*ProbeResult, error)
	callLowRisk      func() (*ProbeResult, error)
	callBadTechnique func() (*ProbeResult, error) // nil if probe has no technique validation
	callBadConfig    func() (*ProbeResult, error) // nil unless probe has additional config validation
}

var contracts = []probeContract{
	{name: "sqli", risk: 3,
		callOutOfScope: func() (*ProbeResult, error) {
			return VerifySQLi(SQLiConfig{URL: "http://evil.example.com/api", Param: "id", Technique: "blind_time", Method: "GET", Boundary: "single_quote",
				ProbeConfig: ProbeConfig{InScope: []string{"safe.example.com"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callLowRisk: func() (*ProbeResult, error) {
			return VerifySQLi(SQLiConfig{URL: "http://localhost/api", Param: "id", Technique: "blind_time", Method: "GET", Boundary: "single_quote",
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 1, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callBadTechnique: func() (*ProbeResult, error) {
			return VerifySQLi(SQLiConfig{URL: "http://localhost/api", Param: "id", Technique: "INVALID", Method: "GET", Boundary: "single_quote",
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
	},
	{name: "xss", risk: 2,
		callOutOfScope: func() (*ProbeResult, error) {
			return VerifyXSS(XSSConfig{URL: "http://evil.example.com/api", Param: "q", Payload: "<script>", Method: "GET",
				ProbeConfig: ProbeConfig{InScope: []string{"safe.example.com"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callLowRisk: func() (*ProbeResult, error) {
			return VerifyXSS(XSSConfig{URL: "http://localhost/api", Param: "q", Payload: "<script>", Method: "GET",
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 1, ThrottleMs: 0, TimeoutSec: 5}})
		},
	},
	{name: "idor", risk: 2,
		callOutOfScope: func() (*ProbeResult, error) {
			return VerifyIDOR(IDORConfig{URL: "http://evil.example.com/api/{id}", ID: "123", Token: "tok", Method: "GET",
				ProbeConfig: ProbeConfig{InScope: []string{"safe.example.com"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callLowRisk: func() (*ProbeResult, error) {
			return VerifyIDOR(IDORConfig{URL: "http://localhost/api/{id}", ID: "123", Token: "tok", Method: "GET",
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 1, ThrottleMs: 0, TimeoutSec: 5}})
		},
	},
	{name: "ssrf", risk: 3,
		callOutOfScope: func() (*ProbeResult, error) {
			return VerifySSRF(SSRFConfig{URL: "http://evil.example.com/api", Param: "url", Method: "GET",
				ProbeConfig: ProbeConfig{InScope: []string{"safe.example.com"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callLowRisk: func() (*ProbeResult, error) {
			return VerifySSRF(SSRFConfig{URL: "http://localhost/api", Param: "url", Method: "GET",
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 1, ThrottleMs: 0, TimeoutSec: 5}})
		},
	},
	{name: "auth", risk: 3,
		callOutOfScope: func() (*ProbeResult, error) {
			return VerifyAuth(AuthConfig{URL: "http://evil.example.com/api", Method: "GET", Token: "tok", Technique: "no_token",
				ProbeConfig: ProbeConfig{InScope: []string{"safe.example.com"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callLowRisk: func() (*ProbeResult, error) {
			return VerifyAuth(AuthConfig{URL: "http://localhost/api", Method: "GET", Token: "tok", Technique: "no_token",
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 1, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callBadTechnique: func() (*ProbeResult, error) {
			return VerifyAuth(AuthConfig{URL: "http://localhost/api", Method: "GET", Token: "tok", Technique: "INVALID",
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
	},
	{name: "authz", risk: 2,
		callOutOfScope: func() (*ProbeResult, error) {
			return VerifyAuthZ(AuthZConfig{URL: "http://evil.example.com/api", Method: "GET", LowPrivToken: "low", HighPrivToken: "high",
				ProbeConfig: ProbeConfig{InScope: []string{"safe.example.com"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callLowRisk: func() (*ProbeResult, error) {
			return VerifyAuthZ(AuthZConfig{URL: "http://localhost/api", Method: "GET", LowPrivToken: "low", HighPrivToken: "high",
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 1, ThrottleMs: 0, TimeoutSec: 5}})
		},
	},
	{name: "rls", risk: 2,
		callOutOfScope: func() (*ProbeResult, error) {
			return VerifyRLS(RLSConfig{ProjectURL: "http://evil.example.com", AnonKey: "key", JWTSecret: "secret-at-least-32-characters-long", Table: "t", TenantA: "a", TenantB: "b",
				ProbeConfig: ProbeConfig{InScope: []string{"safe.example.com"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callLowRisk: func() (*ProbeResult, error) {
			return VerifyRLS(RLSConfig{ProjectURL: "http://localhost", AnonKey: "key", JWTSecret: "secret-at-least-32-characters-long", Table: "t", TenantA: "a", TenantB: "b",
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 1, ThrottleMs: 0, TimeoutSec: 5}})
		},
	},
	{name: "cmdi", risk: 3,
		callOutOfScope: func() (*ProbeResult, error) {
			return VerifyCMDi(CMDiConfig{URL: "http://evil.example.com/api", Param: "cmd", OS: "linux", Method: "GET",
				ProbeConfig: ProbeConfig{InScope: []string{"safe.example.com"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callLowRisk: func() (*ProbeResult, error) {
			return VerifyCMDi(CMDiConfig{URL: "http://localhost/api", Param: "cmd", OS: "linux", Method: "GET",
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 1, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callBadTechnique: func() (*ProbeResult, error) {
			return VerifyCMDi(CMDiConfig{URL: "http://localhost/api", Param: "cmd", OS: "INVALID", Method: "GET",
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
	},
	{name: "lfi", risk: 3,
		callOutOfScope: func() (*ProbeResult, error) {
			return VerifyLFI(LFIConfig{URL: "http://evil.example.com/api", Param: "file", OS: "linux", Method: "GET",
				ProbeConfig: ProbeConfig{InScope: []string{"safe.example.com"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callLowRisk: func() (*ProbeResult, error) {
			return VerifyLFI(LFIConfig{URL: "http://localhost/api", Param: "file", OS: "linux", Method: "GET",
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 1, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callBadTechnique: func() (*ProbeResult, error) {
			return VerifyLFI(LFIConfig{URL: "http://localhost/api", Param: "file", OS: "INVALID", Method: "GET",
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
	},
	{name: "ssti", risk: 3,
		callOutOfScope: func() (*ProbeResult, error) {
			return VerifySSTI(SSTIConfig{URL: "http://evil.example.com/api", Param: "tpl", Engine: "auto", Method: "GET",
				ProbeConfig: ProbeConfig{InScope: []string{"safe.example.com"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callLowRisk: func() (*ProbeResult, error) {
			return VerifySSTI(SSTIConfig{URL: "http://localhost/api", Param: "tpl", Engine: "auto", Method: "GET",
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 1, ThrottleMs: 0, TimeoutSec: 5}})
		},
	},
	{name: "xxe", risk: 3,
		callOutOfScope: func() (*ProbeResult, error) {
			return VerifyXXE(XXEConfig{URL: "http://evil.example.com/api", Method: "POST", Technique: "file_read",
				ProbeConfig: ProbeConfig{InScope: []string{"safe.example.com"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callLowRisk: func() (*ProbeResult, error) {
			return VerifyXXE(XXEConfig{URL: "http://localhost/api", Method: "POST", Technique: "file_read",
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 1, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callBadTechnique: func() (*ProbeResult, error) {
			return VerifyXXE(XXEConfig{URL: "http://localhost/api", Method: "POST", Technique: "INVALID",
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
	},
	{name: "csrf", risk: 2,
		callOutOfScope: func() (*ProbeResult, error) {
			return VerifyCSRF(CSRFConfig{URL: "http://evil.example.com/api", Method: "POST",
				ProbeConfig: ProbeConfig{InScope: []string{"safe.example.com"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callLowRisk: func() (*ProbeResult, error) {
			return VerifyCSRF(CSRFConfig{URL: "http://localhost/api", Method: "POST",
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 1, ThrottleMs: 0, TimeoutSec: 5}})
		},
	},
	{name: "nosql", risk: 3,
		callOutOfScope: func() (*ProbeResult, error) {
			return VerifyNoSQL(NoSQLConfig{URL: "http://evil.example.com/api", Param: "user", Technique: "operator_injection", Method: "POST",
				ProbeConfig: ProbeConfig{InScope: []string{"safe.example.com"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callLowRisk: func() (*ProbeResult, error) {
			return VerifyNoSQL(NoSQLConfig{URL: "http://localhost/api", Param: "user", Technique: "operator_injection", Method: "POST",
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 1, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callBadTechnique: func() (*ProbeResult, error) {
			return VerifyNoSQL(NoSQLConfig{URL: "http://localhost/api", Param: "user", Technique: "INVALID", Method: "POST",
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
	},
	{name: "jwt", risk: 2,
		callOutOfScope: func() (*ProbeResult, error) {
			return VerifyJWT(JWTConfig{URL: "http://evil.example.com/api", Token: testJWT, Technique: "alg_none", Method: "GET",
				ProbeConfig: ProbeConfig{InScope: []string{"safe.example.com"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callLowRisk: func() (*ProbeResult, error) {
			return VerifyJWT(JWTConfig{URL: "http://localhost/api", Token: testJWT, Technique: "alg_none", Method: "GET",
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 1, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callBadTechnique: func() (*ProbeResult, error) {
			return VerifyJWT(JWTConfig{URL: "http://localhost/api", Token: testJWT, Technique: "INVALID", Method: "GET",
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
	},
	{name: "cors", risk: 2,
		callOutOfScope: func() (*ProbeResult, error) {
			return VerifyCORS(CORSConfig{URL: "http://evil.example.com/api", Method: "GET",
				ProbeConfig: ProbeConfig{InScope: []string{"safe.example.com"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callLowRisk: func() (*ProbeResult, error) {
			return VerifyCORS(CORSConfig{URL: "http://localhost/api", Method: "GET",
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 1, ThrottleMs: 0, TimeoutSec: 5}})
		},
	},
	{name: "protopollution", risk: 3,
		callOutOfScope: func() (*ProbeResult, error) {
			return VerifyProtoPollution(ProtoPollutionConfig{URL: "http://evil.example.com/api", Method: "POST", Technique: "proto_assignment",
				ProbeConfig: ProbeConfig{InScope: []string{"safe.example.com"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callLowRisk: func() (*ProbeResult, error) {
			return VerifyProtoPollution(ProtoPollutionConfig{URL: "http://localhost/api", Method: "POST", Technique: "proto_assignment",
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 1, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callBadTechnique: func() (*ProbeResult, error) {
			return VerifyProtoPollution(ProtoPollutionConfig{URL: "http://localhost/api", Method: "POST", Technique: "INVALID",
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
	},
	{name: "graphql", risk: 2,
		callOutOfScope: func() (*ProbeResult, error) {
			return VerifyGraphQL(GraphQLConfig{URL: "http://evil.example.com/api", Technique: "introspection", Method: "POST",
				ProbeConfig: ProbeConfig{InScope: []string{"safe.example.com"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callLowRisk: func() (*ProbeResult, error) {
			return VerifyGraphQL(GraphQLConfig{URL: "http://localhost/api", Technique: "introspection", Method: "POST",
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 1, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callBadTechnique: func() (*ProbeResult, error) {
			return VerifyGraphQL(GraphQLConfig{URL: "http://localhost/api", Technique: "INVALID", Method: "POST",
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
	},
	{name: "race", risk: 4,
		callOutOfScope: func() (*ProbeResult, error) {
			return VerifyRace(RaceConfig{URL: "http://evil.example.com/api", Method: "POST", Concurrency: 5,
				ProbeConfig: ProbeConfig{InScope: []string{"safe.example.com"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callLowRisk: func() (*ProbeResult, error) {
			return VerifyRace(RaceConfig{URL: "http://localhost/api", Method: "POST", Concurrency: 5,
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 1, ThrottleMs: 0, TimeoutSec: 5}})
		},
	},
	{name: "cachepoisoning", risk: 3,
		callOutOfScope: func() (*ProbeResult, error) {
			return VerifyCachePoisoning(CachePoisoningConfig{URL: "http://evil.example.com/api", Technique: "unkeyed_header",
				ProbeConfig: ProbeConfig{InScope: []string{"safe.example.com"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callLowRisk: func() (*ProbeResult, error) {
			return VerifyCachePoisoning(CachePoisoningConfig{URL: "http://localhost/api", Technique: "unkeyed_header",
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 1, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callBadTechnique: func() (*ProbeResult, error) {
			return VerifyCachePoisoning(CachePoisoningConfig{URL: "http://localhost/api", Technique: "INVALID",
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
	},
	{name: "redirect", risk: 2,
		callOutOfScope: func() (*ProbeResult, error) {
			return VerifyRedirect(RedirectConfig{URL: "http://evil.example.com/api", Param: "next", Method: "GET",
				ProbeConfig: ProbeConfig{InScope: []string{"safe.example.com"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callLowRisk: func() (*ProbeResult, error) {
			return VerifyRedirect(RedirectConfig{URL: "http://localhost/api", Param: "next", Method: "GET",
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 1, ThrottleMs: 0, TimeoutSec: 5}})
		},
	},
	{name: "clickjacking", risk: 2,
		callOutOfScope: func() (*ProbeResult, error) {
			return VerifyClickjacking(ClickjackingConfig{URL: "http://evil.example.com/api", Method: "GET",
				ProbeConfig: ProbeConfig{InScope: []string{"safe.example.com"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callLowRisk: func() (*ProbeResult, error) {
			return VerifyClickjacking(ClickjackingConfig{URL: "http://localhost/api", Method: "GET",
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 1, ThrottleMs: 0, TimeoutSec: 5}})
		},
	},
	{name: "headerinjection", risk: 3,
		callOutOfScope: func() (*ProbeResult, error) {
			return VerifyHeaderInjection(HeaderInjectionConfig{URL: "http://evil.example.com/api", Param: "q", Method: "GET",
				ProbeConfig: ProbeConfig{InScope: []string{"safe.example.com"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callLowRisk: func() (*ProbeResult, error) {
			return VerifyHeaderInjection(HeaderInjectionConfig{URL: "http://localhost/api", Param: "q", Method: "GET",
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 1, ThrottleMs: 0, TimeoutSec: 5}})
		},
	},
	{name: "csvinjection", risk: 3,
		callOutOfScope: func() (*ProbeResult, error) {
			return VerifyCSVInjection(CSVInjectionConfig{SubmitURL: "http://evil.example.com/submit", ExportURL: "http://evil.example.com/export", Param: "name", Method: "POST",
				ProbeConfig: ProbeConfig{InScope: []string{"safe.example.com"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callLowRisk: func() (*ProbeResult, error) {
			return VerifyCSVInjection(CSVInjectionConfig{SubmitURL: "http://localhost/submit", ExportURL: "http://localhost/export", Param: "name", Method: "POST",
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 1, ThrottleMs: 0, TimeoutSec: 5}})
		},
	},
	{name: "propertyauthz", risk: 2,
		callOutOfScope: func() (*ProbeResult, error) {
			return VerifyPropertyAuthZ(PropertyAuthZConfig{URL: "http://evil.example.com/api", Method: "GET", HighPrivToken: "high", LowPrivToken: "low",
				ProbeConfig: ProbeConfig{InScope: []string{"safe.example.com"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callLowRisk: func() (*ProbeResult, error) {
			return VerifyPropertyAuthZ(PropertyAuthZConfig{URL: "http://localhost/api", Method: "GET", HighPrivToken: "high", LowPrivToken: "low",
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 1, ThrottleMs: 0, TimeoutSec: 5}})
		},
	},
	{name: "ratelimit", risk: 2,
		callOutOfScope: func() (*ProbeResult, error) {
			return VerifyRateLimit(RateLimitConfig{URL: "http://evil.example.com/api", Method: "POST", BurstCount: 5,
				ProbeConfig: ProbeConfig{InScope: []string{"safe.example.com"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callLowRisk: func() (*ProbeResult, error) {
			return VerifyRateLimit(RateLimitConfig{URL: "http://localhost/api", Method: "POST", BurstCount: 5,
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 1, ThrottleMs: 0, TimeoutSec: 5}})
		},
	},
	{name: "limits", risk: 2,
		callOutOfScope: func() (*ProbeResult, error) {
			return VerifyLimits(LimitsConfig{URL: "http://evil.example.com/api", Technique: "pagination", Param: "limit", Values: []int{1, 100},
				ProbeConfig: ProbeConfig{InScope: []string{"safe.example.com"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callLowRisk: func() (*ProbeResult, error) {
			return VerifyLimits(LimitsConfig{URL: "http://localhost/api", Technique: "pagination", Param: "limit", Values: []int{1, 100},
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 1, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callBadTechnique: func() (*ProbeResult, error) {
			return VerifyLimits(LimitsConfig{URL: "http://localhost/api", Technique: "INVALID",
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
	},
	{name: "websocket", risk: 2,
		callOutOfScope: func() (*ProbeResult, error) {
			return VerifyWebSocket(WebSocketConfig{URL: "ws://evil.example.com/ws", Technique: "ws_injection", Payload: "test",
				ProbeConfig: ProbeConfig{InScope: []string{"safe.example.com"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callLowRisk: func() (*ProbeResult, error) {
			return VerifyWebSocket(WebSocketConfig{URL: "ws://localhost/ws", Technique: "ws_injection", Payload: "test",
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 1, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callBadTechnique: func() (*ProbeResult, error) {
			return VerifyWebSocket(WebSocketConfig{URL: "ws://localhost/ws", Technique: "INVALID", Payload: "test",
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
	},
	{name: "grpc", risk: 2,
		callOutOfScope: func() (*ProbeResult, error) {
			return VerifyGRPC(GRPCConfig{URL: "http://evil.example.com:50051", Technique: "grpc_reflection",
				ProbeConfig: ProbeConfig{InScope: []string{"safe.example.com"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callLowRisk: func() (*ProbeResult, error) {
			return VerifyGRPC(GRPCConfig{URL: "http://localhost:50051", Technique: "grpc_reflection",
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 1, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callBadTechnique: func() (*ProbeResult, error) {
			return VerifyGRPC(GRPCConfig{URL: "http://localhost:50051", Technique: "INVALID",
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
	},
	{name: "ldap", risk: 3,
		callOutOfScope: func() (*ProbeResult, error) {
			return VerifyLDAP(LDAPConfig{URL: "http://evil.example.com/api", Param: "uid", Technique: "ldap_filter_injection", Method: "GET",
				ProbeConfig: ProbeConfig{InScope: []string{"safe.example.com"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callLowRisk: func() (*ProbeResult, error) {
			return VerifyLDAP(LDAPConfig{URL: "http://localhost/api", Param: "uid", Technique: "ldap_filter_injection", Method: "GET",
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 1, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callBadTechnique: func() (*ProbeResult, error) {
			return VerifyLDAP(LDAPConfig{URL: "http://localhost/api", Param: "uid", Technique: "INVALID", Method: "GET",
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
	},
	{name: "xpath", risk: 3,
		callOutOfScope: func() (*ProbeResult, error) {
			return VerifyXPath(XPathConfig{URL: "http://evil.example.com/api", Param: "q", Technique: "xpath_injection", Method: "GET",
				ProbeConfig: ProbeConfig{InScope: []string{"safe.example.com"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callLowRisk: func() (*ProbeResult, error) {
			return VerifyXPath(XPathConfig{URL: "http://localhost/api", Param: "q", Technique: "xpath_injection", Method: "GET",
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 1, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callBadTechnique: func() (*ProbeResult, error) {
			return VerifyXPath(XPathConfig{URL: "http://localhost/api", Param: "q", Technique: "INVALID", Method: "GET",
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
	},
	{name: "fileupload", risk: 3,
		callOutOfScope: func() (*ProbeResult, error) {
			return VerifyFileUpload(FileUploadConfig{URL: "http://evil.example.com/upload", FieldName: "file", Filename: "test.php", Content: "test", MIMEType: "application/octet-stream", Technique: "extension_bypass", Method: "POST",
				ProbeConfig: ProbeConfig{InScope: []string{"safe.example.com"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callLowRisk: func() (*ProbeResult, error) {
			return VerifyFileUpload(FileUploadConfig{URL: "http://localhost/upload", FieldName: "file", Filename: "test.php", Content: "test", MIMEType: "application/octet-stream", Technique: "extension_bypass", Method: "POST",
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 1, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callBadTechnique: func() (*ProbeResult, error) {
			return VerifyFileUpload(FileUploadConfig{URL: "http://localhost/upload", FieldName: "file", Filename: "test.php", Content: "test", MIMEType: "application/octet-stream", Technique: "INVALID", Method: "POST",
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
	},
	{name: "massassignment", risk: 3,
		callOutOfScope: func() (*ProbeResult, error) {
			return VerifyMassAssignment(MassAssignmentConfig{URL: "http://evil.example.com/api/user", Method: "PUT", Body: `{"name":"test"}`, WatchFields: []string{"role"}, Token: "tok",
				ProbeConfig: ProbeConfig{InScope: []string{"safe.example.com"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callLowRisk: func() (*ProbeResult, error) {
			return VerifyMassAssignment(MassAssignmentConfig{URL: "http://localhost/api/user", Method: "PUT", Body: `{"name":"test"}`, WatchFields: []string{"role"}, Token: "tok",
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 1, ThrottleMs: 0, TimeoutSec: 5}})
		},
		callBadConfig: func() (*ProbeResult, error) {
			return VerifyMassAssignment(MassAssignmentConfig{URL: "http://localhost/api/user", Method: "PUT", Body: `{"name":"test"}`, WatchFields: []string{}, Token: "tok",
				ProbeConfig: ProbeConfig{InScope: []string{"localhost"}, MaxRisk: 0, ThrottleMs: 0, TimeoutSec: 5}})
		},
	},
}

func TestContracts_ScopeEnforcement(t *testing.T) {
	for _, c := range contracts {
		t.Run(c.name, func(t *testing.T) {
			result, err := c.callOutOfScope()
			assertScopeErr(t, result, err)
		})
	}
}

func TestContracts_MaxRiskEnforcement(t *testing.T) {
	for _, c := range contracts {
		t.Run(c.name, func(t *testing.T) {
			result, err := c.callLowRisk()
			assertScopeErr(t, result, err)
		})
	}
}

func TestContracts_TechniqueValidation(t *testing.T) {
	for _, c := range contracts {
		if c.callBadTechnique == nil {
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			result, err := c.callBadTechnique()
			if result != nil {
				t.Fatal("expected nil result for invalid technique")
			}
			var scopeErr *ScopeError
			if !errors.As(err, &scopeErr) {
				t.Fatalf("expected *ScopeError, got %T: %v", err, err)
			}
		})
	}
}

func TestContracts_AdditionalConfigValidation(t *testing.T) {
	for _, c := range contracts {
		if c.callBadConfig == nil {
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			result, err := c.callBadConfig()
			if result != nil {
				t.Fatal("expected nil result for invalid config")
			}
			var scopeErr *ScopeError
			if !errors.As(err, &scopeErr) {
				t.Fatalf("expected *ScopeError, got %T: %v", err, err)
			}
		})
	}
}

func TestContracts_NoForbiddenJudgmentJSONFields(t *testing.T) {
	types := []interface{}{
		ProbeResult{},
		RoundResult{},
		SQLiTimeMeasurements{},
		SQLiBooleanMeasurements{},
		SQLiErrorMeasurements{},
		XSSMeasurements{},
		IDORMeasurements{},
		SSRFMeasurements{},
		AuthMeasurements{},
		RLSMeasurements{},
		CMDiTimeMeasurements{},
		LFIMeasurements{},
		SSTIMeasurements{},
		SSTIProbeResult{},
		XXEMeasurements{},
		CSRFMeasurements{},
		NoSQLMeasurements{},
		JWTMeasurements{},
		CORSMeasurements{},
		CORSProbeResult{},
		ProtoPollutionMeasurements{},
		GraphQLMeasurements{},
		RaceMeasurements{},
		CachePoisoningMeasurements{},
		ClickjackingMeasurements{},
		HeaderInjectionMeasurements{},
		RedirectMeasurements{},
		CSVInjectionMeasurements{},
		AuthZMeasurements{},
		OriginCheckResult{},
		WebSocketMeasurements{},
		PropertyAuthZMeasurements{},
		WatchFieldResult{},
		RateLimitMeasurements{},
		RateLimitMeasurementSet{},
		LimitsMeasurements{},
		LimitsPaginationRound{},
		LimitsUploadRound{},
		LimitsResponseRound{},
		LDAPMeasurements{},
		GRPCMeasurements{},
		XPathMeasurements{},
		FileUploadMeasurements{},
		MassAssignmentMeasurements{},
		MassAssignFieldResult{},
	}
	for _, typ := range types {
		assertNoForbiddenJSONTags(t, reflect.TypeOf(typ))
	}
}

// forbiddenOutcomeWords are substrings that presume a security outcome. A
// technique or vuln_type name must describe what is measured, never the verdict.
var forbiddenOutcomeWords = []string{"bypass", "escalation", "exploit", "rce", "forge", "extract"}

// sanctionedOutcomeNames are the two names the refocus spec explicitly keeps
// (file-upload construction techniques). "bypass" there names the file-type
// control being probed; the construction is recorded neutrally in the
// measurement. No new name may join this list.
var sanctionedOutcomeNames = map[string]bool{
	"extension_bypass": true,
	"mime_bypass":      true,
	"auth_bypass":      true, // payload category retained by the seed set, not a verify verdict
}

// TestContracts_NoOutcomePresumingTechniqueNames asserts that the technique and
// vuln_type identifiers the CLI knows about do not presume an outcome.
func TestContracts_NoOutcomePresumingTechniqueNames(t *testing.T) {
	// Names are snake_case; compare per segment so "forced_browsing" is not
	// flagged for the "rce" inside "forced".
	check := func(kind, name string) {
		if sanctionedOutcomeNames[name] {
			return
		}
		for _, seg := range strings.Split(strings.ToLower(name), "_") {
			for _, w := range forbiddenOutcomeWords {
				if seg == w {
					t.Errorf("%s %q contains outcome-presuming word %q", kind, name, w)
				}
			}
		}
	}
	for name := range enums.ValidTechniques {
		check("technique", name)
	}
	for name := range enums.ValidVulnTypes {
		check("vuln_type", name)
	}
}

func assertNoForbiddenJSONTags(t *testing.T, typ reflect.Type) {
	t.Helper()
	for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Array {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct {
		return
	}
	forbidden := map[string]bool{
		"status":     true,
		"confidence": true,
		"confirmed":  true,
		"safe":       true,
		"potential":  true,
	}
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		tag := field.Tag.Get("json")
		if tag != "" && tag != "-" {
			name := strings.Split(tag, ",")[0]
			if forbidden[name] {
				t.Fatalf("%s.%s uses forbidden judgment JSON field %q", typ.Name(), field.Name, name)
			}
		}
		assertNoForbiddenJSONTags(t, field.Type)
	}
}
