package report

import (
	"fmt"
	"html/template"
	"io"
	"strings"
)

type htmlReportV1 struct {
	Report
	Status string
	Counts map[string]int
}

var htmlTemplateV1 = template.Must(template.New("report-v1").Funcs(template.FuncMap{
	"add": func(value int) int {
		return value + 1
	},
	"lower": func(value any) string {
		return strings.ToLower(fmt.Sprint(value))
	},
	"sum": func(a, b int) int {
		return a + b
	},
	"percent": func(count, total int) int {
		if total == 0 {
			return 0
		}

		return count * 100 / total
	},
}).Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>frameseven security report - {{.Target}}</title>
<style>
:root {
  color-scheme: dark;
  --background: #070a10;
  --surface: #0d121c;
  --surface-raised: #121a27;
  --surface-soft: #171f2d;
  --border: #263244;
  --border-strong: #35445b;
  --text: #edf2f7;
  --muted: #91a0b5;
  --subtle: #64748b;
  --accent: #67e8f9;
  --critical: #fb7185;
  --high: #fb923c;
  --medium: #facc15;
  --low: #38bdf8;
  --info: #a78bfa;
}

* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  margin: 0;
  background:
    radial-gradient(circle at 15% -10%, rgba(56, 189, 248, .11), transparent 30rem),
    radial-gradient(circle at 90% 5%, rgba(167, 139, 250, .08), transparent 26rem),
    var(--background);
  color: var(--text);
  font: 15px/1.6 Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}
a { color: inherit; text-decoration: none; }
code, pre { font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace; }
.muted { color: var(--muted); }

.layout {
  display: grid;
  grid-template-columns: 270px minmax(0, 1fr);
  width: min(1480px, 100%);
  min-height: 100vh;
  margin: 0 auto;
}

.sidebar {
  position: sticky;
  top: 0;
  height: 100vh;
  padding: 30px 22px;
  border-right: 1px solid var(--border);
  background: rgba(7, 10, 16, .82);
  backdrop-filter: blur(18px);
  overflow-y: auto;
}
.brand { display: flex; align-items: center; gap: 11px; margin-bottom: 34px; }
.brand-mark {
  display: grid;
  width: 38px;
  height: 38px;
  place-items: center;
  border: 1px solid rgba(103, 232, 249, .5);
  border-radius: 10px;
  background: rgba(103, 232, 249, .08);
  color: var(--accent);
  font-size: 18px;
  font-weight: 900;
}
.brand strong { display: block; font-size: 16px; letter-spacing: .01em; }
.brand span { color: var(--muted); font-size: 12px; }
.nav-label {
  margin: 24px 10px 8px;
  color: var(--subtle);
  font-size: 10px;
  font-weight: 800;
  letter-spacing: .15em;
  text-transform: uppercase;
}
.nav-link {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  padding: 9px 10px;
  border-radius: 8px;
  color: var(--muted);
  font-size: 13px;
  transition: background .15s ease, color .15s ease;
}
.nav-link:hover { background: var(--surface-soft); color: var(--text); }
.nav-link .count {
  min-width: 24px;
  padding: 1px 7px;
  border: 1px solid var(--border);
  border-radius: 999px;
  color: var(--subtle);
  text-align: center;
}
.finding-link { align-items: flex-start; }
.finding-link span:first-child {
  display: -webkit-box;
  overflow: hidden;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 2;
}

.content { min-width: 0; padding: 42px clamp(24px, 4vw, 64px) 80px; }
.hero {
  position: relative;
  overflow: hidden;
  padding: clamp(26px, 5vw, 48px);
  border: 1px solid var(--border-strong);
  border-radius: 20px;
  background: linear-gradient(135deg, rgba(18, 26, 39, .98), rgba(10, 15, 24, .98));
  box-shadow: 0 30px 80px rgba(0, 0, 0, .28);
}
.hero::after {
  position: absolute;
  right: -90px;
  bottom: -130px;
  width: 340px;
  height: 340px;
  border: 1px solid rgba(103, 232, 249, .12);
  border-radius: 50%;
  box-shadow: 0 0 0 45px rgba(103, 232, 249, .025), 0 0 0 90px rgba(103, 232, 249, .015);
  content: "";
}
.eyebrow {
  margin-bottom: 14px;
  color: var(--accent);
  font-size: 11px;
  font-weight: 800;
  letter-spacing: .16em;
  text-transform: uppercase;
}
h1, h2, h3, h4, p { margin-top: 0; }
h1 { max-width: 760px; margin-bottom: 12px; font-size: clamp(30px, 5vw, 52px); line-height: 1.08; letter-spacing: -.035em; }
.target { max-width: 850px; margin: 0; color: var(--muted); font: 14px/1.6 "SFMono-Regular", Consolas, monospace; overflow-wrap: anywhere; }
.hero-meta { display: flex; flex-wrap: wrap; gap: 10px 22px; margin-top: 28px; color: var(--muted); font-size: 13px; }
.status {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  color: var(--text);
  font-weight: 700;
  text-transform: capitalize;
}
.status::before { width: 8px; height: 8px; border-radius: 50%; background: #4ade80; box-shadow: 0 0 14px rgba(74, 222, 128, .7); content: ""; }
.status.incomplete::before { background: var(--high); box-shadow: 0 0 14px rgba(251, 146, 60, .7); }

.section { margin-top: 42px; scroll-margin-top: 24px; }
.section-heading { display: flex; align-items: flex-end; justify-content: space-between; gap: 20px; margin-bottom: 16px; }
.section-heading h2 { margin-bottom: 3px; font-size: 21px; letter-spacing: -.015em; }
.section-heading p { margin: 0; color: var(--muted); font-size: 13px; }

.metrics { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }
.metric {
  padding: 20px;
  border: 1px solid var(--border);
  border-radius: 13px;
  background: var(--surface);
}
.metric-label { color: var(--muted); font-size: 12px; }
.metric-value { display: block; margin-top: 6px; font-size: 28px; font-weight: 800; line-height: 1.1; }
.metric-note { display: block; margin-top: 7px; color: var(--subtle); font-size: 11px; }

.panel {
  border: 1px solid var(--border);
  border-radius: 14px;
  background: var(--surface);
  overflow: hidden;
}
.panel-header { padding: 18px 20px; border-bottom: 1px solid var(--border); }
.panel-header h3 { margin: 0; font-size: 15px; }
.panel-body { padding: 20px; }
.overview-grid { display: grid; grid-template-columns: minmax(0, 1.25fr) minmax(280px, .75fr); gap: 14px; margin-top: 14px; }

.severity-row { display: grid; grid-template-columns: 76px 1fr 34px; align-items: center; gap: 12px; padding: 8px 0; }
.severity-name { color: var(--muted); font-size: 12px; font-weight: 700; text-transform: uppercase; }
.severity-track { height: 8px; border-radius: 999px; background: var(--surface-soft); overflow: hidden; }
.severity-fill { min-width: 2px; height: 100%; border-radius: inherit; }
.severity-fill.critical { background: var(--critical); }
.severity-fill.high { background: var(--high); }
.severity-fill.medium { background: var(--medium); }
.severity-fill.low { background: var(--low); }
.severity-fill.info { background: var(--info); }
.severity-count { font-weight: 800; text-align: right; }

.surface-list { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 1px; background: var(--border); }
.surface-item { min-width: 0; padding: 16px 18px; background: var(--surface); }
.surface-item span { display: block; color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .08em; }
.surface-item strong { display: block; margin-top: 4px; overflow-wrap: anywhere; }

.inventory { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; margin-top: 14px; }
.data-list { max-height: 320px; margin: 0; padding: 0; list-style: none; overflow: auto; }
.data-list li { padding: 10px 0; border-bottom: 1px solid var(--border); color: #cbd5e1; overflow-wrap: anywhere; }
.data-list li:last-child { border-bottom: 0; }
.data-list code { color: var(--accent); font-size: 12px; }
.empty { color: var(--subtle); font-style: italic; }

.errors { margin: 0; padding: 0; list-style: none; }
.errors li { padding: 13px 0; border-bottom: 1px solid var(--border); color: #fecaca; }
.errors li:last-child { border-bottom: 0; }
.errors strong { color: var(--high); }

.findings { display: grid; gap: 16px; }
.finding {
  position: relative;
  border: 1px solid var(--border);
  border-radius: 15px;
  background: var(--surface);
  overflow: hidden;
  scroll-margin-top: 24px;
}
.finding::before { position: absolute; inset: 0 auto 0 0; width: 4px; background: var(--subtle); content: ""; }
.finding.critical::before { background: var(--critical); }
.finding.high::before { background: var(--high); }
.finding.medium::before { background: var(--medium); }
.finding.low::before { background: var(--low); }
.finding.info::before { background: var(--info); }
.finding-head { padding: 22px 24px 18px 28px; border-bottom: 1px solid var(--border); }
.finding-kicker { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin-bottom: 12px; }
.badge { padding: 3px 9px; border: 1px solid var(--border-strong); border-radius: 999px; color: var(--muted); font-size: 10px; font-weight: 800; letter-spacing: .07em; text-transform: uppercase; }
.badge.severity { color: var(--text); }
.critical .badge.severity { border-color: rgba(251, 113, 133, .5); color: var(--critical); }
.high .badge.severity { border-color: rgba(251, 146, 60, .5); color: var(--high); }
.medium .badge.severity { border-color: rgba(250, 204, 21, .5); color: var(--medium); }
.low .badge.severity { border-color: rgba(56, 189, 248, .5); color: var(--low); }
.info .badge.severity { border-color: rgba(167, 139, 250, .5); color: var(--info); }
.finding h3 { margin-bottom: 8px; font-size: 20px; line-height: 1.3; }
.finding-description { max-width: 900px; margin: 0; color: #cbd5e1; }
.finding-body { padding: 20px 24px 24px 28px; }
.references { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 18px; }
.reference { padding: 5px 9px; border-radius: 7px; background: var(--surface-soft); color: var(--muted); font-size: 12px; }
.next-steps { margin: 0; padding-left: 20px; color: #cbd5e1; }
.next-steps li + li { margin-top: 7px; }
details { margin-top: 10px; border: 1px solid var(--border); border-radius: 9px; background: #090d14; overflow: hidden; }
summary { padding: 12px 14px; color: var(--accent); cursor: pointer; font-size: 12px; font-weight: 800; letter-spacing: .04em; text-transform: uppercase; }
pre { max-height: 440px; margin: 0; padding: 16px; border-top: 1px solid var(--border); color: #cbd5e1; font-size: 12px; line-height: 1.55; white-space: pre-wrap; overflow: auto; overflow-wrap: anywhere; }

.no-findings { padding: 42px 24px; color: var(--muted); text-align: center; }
footer { margin-top: 48px; color: var(--subtle); font-size: 12px; text-align: center; }

@media (max-width: 980px) {
  .layout { display: block; }
  .sidebar { position: static; width: 100%; height: auto; border-right: 0; border-bottom: 1px solid var(--border); }
  .sidebar nav { display: none; }
  .brand { margin: 0; }
  .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .overview-grid, .inventory { grid-template-columns: 1fr; }
}
@media (max-width: 560px) {
  .content { padding: 22px 14px 60px; }
  .hero { border-radius: 14px; }
  .metrics, .surface-list { grid-template-columns: 1fr; }
  .finding-head, .finding-body { padding-left: 22px; padding-right: 18px; }
}
@media print {
  :root { color-scheme: light; --background:#fff; --surface:#fff; --surface-raised:#fff; --surface-soft:#f4f6f8; --border:#d7dde5; --border-strong:#b8c2cf; --text:#111827; --muted:#4b5563; --subtle:#6b7280; }
  body { background: #fff; color: #111827; }
  .layout { display: block; }
  .sidebar { display: none; }
  .content { padding: 0; }
  .hero, .panel, .finding, .metric { break-inside: avoid; box-shadow: none; }
  details { break-inside: avoid; }
  details > * { display: block; }
}
</style>
</head>
<body>
<div class="layout">
<aside class="sidebar">
  <div class="brand">
    <div class="brand-mark">F7</div>
    <div><strong>frameseven</strong><span>Security report v1</span></div>
  </div>
  <nav>
    <div class="nav-label">Report</div>
    <a class="nav-link" href="#overview"><span>Executive overview</span></a>
    <a class="nav-link" href="#surface"><span>Attack surface</span></a>
    {{if .Errors}}<a class="nav-link" href="#errors"><span>Scan errors</span><span class="count">{{len .Errors}}</span></a>{{end}}
    <a class="nav-link" href="#findings"><span>Findings</span><span class="count">{{len .Findings}}</span></a>
    {{if .Findings}}
    <div class="nav-label">Finding index</div>
    {{range $index, $finding := .Findings}}
    <a class="nav-link finding-link" href="#finding-{{add $index}}">
      <span>{{$finding.Title}}</span><span class="count">{{add $index}}</span>
    </a>
    {{end}}
    {{end}}
  </nav>
</aside>

<main class="content">
  <header class="hero">
    <div class="eyebrow">Offensive security assessment</div>
    <h1>Web application security report</h1>
    <p class="target">{{.Target}}</p>
    <div class="hero-meta">
      <span class="status {{.Status}}">{{.Status}}</span>
      <span>Started {{.StartedAt.Format "January 2, 2006 at 15:04 MST"}}</span>
      <span>Duration {{.Duration}}</span>
      <span>Schema {{.SchemaVersion}}</span>
    </div>
  </header>

  <section class="section" id="overview">
    <div class="section-heading">
      <div><h2>Executive overview</h2><p>Assessment outcome and risk distribution.</p></div>
    </div>
    <div class="metrics">
      <div class="metric"><span class="metric-label">Total findings</span><strong class="metric-value">{{len .Findings}}</strong><span class="metric-note">Across all completed tools</span></div>
      <div class="metric"><span class="metric-label">Critical and high</span><strong class="metric-value">{{sum (index .Counts "CRITICAL") (index .Counts "HIGH")}}</strong><span class="metric-note">Combined urgent findings</span></div>
      <div class="metric"><span class="metric-label">Mapped endpoints</span><strong class="metric-value">{{len .Surface.Endpoints}}</strong><span class="metric-note">Discovered during reconnaissance</span></div>
      <div class="metric"><span class="metric-label">Tool errors</span><strong class="metric-value">{{len .Errors}}</strong><span class="metric-note">May affect report completeness</span></div>
    </div>
    <div class="overview-grid">
      <div class="panel">
        <div class="panel-header"><h3>Severity distribution</h3></div>
        <div class="panel-body">
          <div class="severity-row"><span class="severity-name">Critical</span><div class="severity-track"><div class="severity-fill critical" style="width:{{percent (index .Counts "CRITICAL") (len .Findings)}}%"></div></div><span class="severity-count">{{index .Counts "CRITICAL"}}</span></div>
          <div class="severity-row"><span class="severity-name">High</span><div class="severity-track"><div class="severity-fill high" style="width:{{percent (index .Counts "HIGH") (len .Findings)}}%"></div></div><span class="severity-count">{{index .Counts "HIGH"}}</span></div>
          <div class="severity-row"><span class="severity-name">Medium</span><div class="severity-track"><div class="severity-fill medium" style="width:{{percent (index .Counts "MEDIUM") (len .Findings)}}%"></div></div><span class="severity-count">{{index .Counts "MEDIUM"}}</span></div>
          <div class="severity-row"><span class="severity-name">Low</span><div class="severity-track"><div class="severity-fill low" style="width:{{percent (index .Counts "LOW") (len .Findings)}}%"></div></div><span class="severity-count">{{index .Counts "LOW"}}</span></div>
          <div class="severity-row"><span class="severity-name">Info</span><div class="severity-track"><div class="severity-fill info" style="width:{{percent (index .Counts "INFO") (len .Findings)}}%"></div></div><span class="severity-count">{{index .Counts "INFO"}}</span></div>
        </div>
      </div>
      <div class="panel">
        <div class="panel-header"><h3>Assessment scope</h3></div>
        <div class="surface-list">
          <div class="surface-item"><span>Host</span><strong>{{.Surface.Host}}</strong></div>
          <div class="surface-item"><span>Technologies</span><strong>{{len .Surface.Technologies}}</strong></div>
          <div class="surface-item"><span>Parameters</span><strong>{{len .Surface.Params}}</strong></div>
          <div class="surface-item"><span>Sensitive files</span><strong>{{len .Surface.SensitiveFiles}}</strong></div>
        </div>
      </div>
    </div>
  </section>

  <section class="section" id="surface">
    <div class="section-heading">
      <div><h2>Attack surface</h2><p>Assets and input points observed during reconnaissance.</p></div>
    </div>
    <div class="inventory">
      <div class="panel">
        <div class="panel-header"><h3>Technologies</h3></div>
        <div class="panel-body">
          {{if .Surface.Technologies}}<ul class="data-list">{{range .Surface.Technologies}}<li><strong>{{.Name}}{{if .Version}} {{.Version}}{{end}}</strong><br><span class="muted">{{.Source}}</span></li>{{end}}</ul>{{else}}<div class="empty">No technologies identified.</div>{{end}}
        </div>
      </div>
      <div class="panel">
        <div class="panel-header"><h3>Endpoints</h3></div>
        <div class="panel-body">
          {{if .Surface.Endpoints}}<ul class="data-list">{{range .Surface.Endpoints}}<li><code>{{.}}</code></li>{{end}}</ul>{{else}}<div class="empty">No additional endpoints discovered.</div>{{end}}
        </div>
      </div>
      <div class="panel">
        <div class="panel-header"><h3>Parameters</h3></div>
        <div class="panel-body">
          {{if .Surface.Params}}<ul class="data-list">{{range .Surface.Params}}<li><strong>{{.Name}}</strong> <span class="muted">{{.Method}}</span><br><code>{{.Endpoint}}</code></li>{{end}}</ul>{{else}}<div class="empty">No parameters discovered.</div>{{end}}
        </div>
      </div>
      <div class="panel">
        <div class="panel-header"><h3>Sensitive files</h3></div>
        <div class="panel-body">
          {{if .Surface.SensitiveFiles}}<ul class="data-list">{{range .Surface.SensitiveFiles}}<li><code>{{.}}</code></li>{{end}}</ul>{{else}}<div class="empty">No sensitive files confirmed.</div>{{end}}
        </div>
      </div>
    </div>
  </section>

  {{if .Errors}}
  <section class="section" id="errors">
    <div class="section-heading">
      <div><h2>Scan errors</h2><p>Tools or requests that did not complete successfully.</p></div>
    </div>
    <div class="panel"><div class="panel-body"><ul class="errors">{{range .Errors}}<li><strong>{{.Module}}</strong><br>{{.Message}}</li>{{end}}</ul></div></div>
  </section>
  {{end}}

  <section class="section" id="findings">
    <div class="section-heading">
      <div><h2>Security findings</h2><p>Technical evidence and recommended remediation steps.</p></div>
    </div>
    {{if .Findings}}
    <div class="findings">
      {{range $index, $finding := .Findings}}
      <article class="finding {{lower $finding.Severity}}" id="finding-{{add $index}}">
        <div class="finding-head">
          <div class="finding-kicker">
            <span class="badge severity">{{$finding.Severity}}</span>
            <span class="badge">{{$finding.Module}}</span>
            {{if $finding.CVSS}}<span class="badge">CVSS {{printf "%.1f" $finding.CVSS}}</span>{{end}}
          </div>
          <h3>{{add $index}}. {{$finding.Title}}</h3>
          <p class="finding-description">{{$finding.Description}}</p>
        </div>
        <div class="finding-body">
          {{if or $finding.CWE $finding.OWASP}}
          <div class="references">
            {{if $finding.CWE}}<span class="reference">{{$finding.CWE}}</span>{{end}}
            {{if $finding.OWASP}}<span class="reference">{{$finding.OWASP}}</span>{{end}}
          </div>
          {{end}}
          {{if $finding.Evidence.Extracted}}<details open><summary>Extracted evidence</summary><pre>{{$finding.Evidence.Extracted}}</pre></details>{{end}}
          {{if $finding.Evidence.Request}}<details><summary>HTTP request</summary><pre>{{$finding.Evidence.Request}}</pre></details>{{end}}
          {{if $finding.Evidence.Response}}<details><summary>HTTP response</summary><pre>{{$finding.Evidence.Response}}</pre></details>{{end}}
          {{if $finding.NextSteps}}
          <h4>Recommended next steps</h4>
          <ul class="next-steps">{{range $finding.NextSteps}}<li>{{.}}</li>{{end}}</ul>
          {{end}}
        </div>
      </article>
      {{end}}
    </div>
    {{else}}
    <div class="panel no-findings">No findings were recorded during this scan.</div>
    {{end}}
  </section>

  <footer>Generated by frameseven CLI v1 · Treat this report as sensitive security data.</footer>
</main>
</div>
</body>
</html>`))

// WriteHTML renders a self-contained HTML security report.
func WriteHTML(w io.Writer, rep Report) error {
	counts := map[string]int{}
	for _, item := range rep.Findings {
		counts[string(item.Severity)]++
	}

	return htmlTemplateV1.Execute(w, htmlReportV1{
		Report: rep,
		Status: reportStatus(rep),
		Counts: counts,
	})
}
