"""HTML report generation (T55 subset)."""
import html
import json
from typing import Any

_ALLOWED_CSS = frozenset({"passed", "failed", "provider_error", "not_run", "unknown"})


def _safe_css_class(name: str) -> str:
    return name if name in _ALLOWED_CSS else "unknown"


def render_html_report(
    title: str,
    cases: list[dict[str, Any]],
    metrics: dict[str, Any],
) -> str:
    rows = []
    for c in cases:
        outcome = str(c.get("outcome", ""))
        cls = _safe_css_class(outcome)
        rows.append(
            f"<tr class='{cls}'><td>{html.escape(str(c.get('name', '')))}</td>"
            f"<td>{html.escape(outcome)}</td>"
            f"<td>{html.escape(str(c.get('detail', '')))}</td>"
            f"<td>{html.escape(str(c.get('elapsed_ms', '')))}</td></tr>"
        )
    metrics_json = html.escape(json.dumps(metrics, indent=2))
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{html.escape(title)}</title>
<style>
body{{font-family:system-ui,sans-serif;margin:2rem;}}
table{{border-collapse:collapse;width:100%;}}
th,td{{border:1px solid #ccc;padding:.5rem;text-align:left;}}
.passed{{background:#e8f5e9;}}.failed{{background:#ffebee;}}
.provider_error{{background:#fff3e0;}}.not_run{{background:#f5f5f5;}}
.unknown{{background:#eceff1;}}
.disclaimer{{color:#666;font-size:.9rem;margin-top:1.5rem;}}
</style></head><body>
<h1>{html.escape(title)}</h1>
<p class="disclaimer">Illustrative integration metrics only. No cryptographic proof claim.</p>
<table><thead><tr><th>Case</th><th>Outcome</th><th>Detail</th><th>Elapsed (ms)</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<h2>Metrics</h2><pre>{metrics_json}</pre>
</body></html>"""


def render_provider_report(report: dict[str, Any]) -> str:
    """Render a provider-run report without interpreting provider-controlled text."""
    provider = report.get("provider", {})
    readiness_rows = []
    for operation, state in report.get("operation_readiness", {}).items():
        readiness_rows.append(
            "<tr>"
            f"<td>{html.escape(str(operation))}</td>"
            f"<td>{html.escape(str(state))}</td>"
            "</tr>"
        )
    timing_rows = []
    for stage, measurement in report.get("benchmark", {}).get("stages", {}).items():
        timing_rows.append(
            "<tr>"
            f"<td>{html.escape(str(stage))}</td>"
            f"<td>{html.escape(str(measurement.get('status', 'not_run')))}</td>"
            f"<td>{html.escape(str(measurement.get('elapsed_ms', '')))}</td>"
            "</tr>"
        )
    size_rows = []
    for name, value in report.get("artifacts", {}).get("sizes_bytes", {}).items():
        size_rows.append(
            f"<tr><td>{html.escape(str(name))}</td><td>{html.escape(str(value))}</td></tr>"
        )
    case_rows = []
    for case in report.get("cases", []):
        outcome = str(case.get("outcome", "unknown"))
        case_rows.append(
            f"<tr class='{_safe_css_class(outcome)}'>"
            f"<td>{html.escape(str(case.get('name', '')))}</td>"
            f"<td>{html.escape(outcome)}</td>"
            f"<td>{html.escape(str(case.get('detail', '')))}</td>"
            "</tr>"
        )
    manifest_path = html.escape(str(provider.get("manifest_path", "")), quote=True)
    support_path = provider.get("support_path")
    support_line = (
        f"<p>Support: <a href='{html.escape(str(support_path), quote=True)}'>"
        f"{html.escape(str(support_path))}</a></p>"
        if support_path else "<p>Support: not provided</p>"
    )
    profiles = ", ".join(str(item) for item in provider.get("profiles", []))
    leakage = report.get("leakage", {})
    support = report.get("support", {})
    support_rows = []
    for claim in support.get("claims", []):
        support_rows.append(
            "<tr>"
            f"<td>{html.escape(str(claim.get('id', '')))}</td>"
            f"<td>{html.escape(str(claim.get('status', '')))}</td>"
            f"<td>{html.escape(str(claim.get('implementation_profile', '')))}</td>"
            f"<td>{html.escape(str(claim.get('circuit', '')))}</td>"
            "</tr>"
        )
    benchmark_json = html.escape(json.dumps(report.get("benchmark", {}), indent=2))
    support_json = html.escape(json.dumps(support, indent=2))
    leakage_json = html.escape(json.dumps(leakage, indent=2))
    leakage_markup = render_privacy_section(leakage) if leakage.get('cases') else f'<pre>{leakage_json}</pre>'
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Provider report</title>
<style>
body{{font-family:system-ui,sans-serif;margin:2rem;max-width:1100px}}
table{{border-collapse:collapse;width:100%;margin-bottom:1.5rem}}
th,td{{border:1px solid #ccc;padding:.5rem;text-align:left}}
.passed,.ready{{background:#e8f5e9}}.failed,.provider_error{{background:#ffebee}}
.not_run,.unknown{{background:#f5f5f5}}pre{{white-space:pre-wrap}}
</style></head><body>
<h1>Provider run report</h1>
<h2>Provider</h2>
<p><strong>{html.escape(str(provider.get('title', 'unknown')))}</strong>
({html.escape(str(provider.get('id', 'unknown')))}) — {html.escape(str(provider.get('kind', 'unknown')))}</p>
<p>Profiles: {html.escape(profiles)}</p>
<p>Manifest: <a href='{manifest_path}'>{manifest_path}</a></p>{support_line}
<h2>Semantic support</h2><p>Status: {html.escape(str(support.get('status', 'not_provided')))}</p>
<table><tr><th>Claim</th><th>Status</th><th>Profile</th><th>Circuit</th></tr>{''.join(support_rows)}</table>
<details><summary>Support JSON</summary><pre>{support_json}</pre></details>
<h2>Operation readiness</h2><table><tr><th>Operation</th><th>Status</th></tr>{''.join(readiness_rows)}</table>
<h2>Stage timings</h2><table><tr><th>Stage</th><th>Status</th><th>Elapsed (ms)</th></tr>{''.join(timing_rows)}</table>
<h2>Artifact sizes</h2><table><tr><th>Artifact</th><th>Bytes</th></tr>{''.join(size_rows)}</table>
<h2>Cases</h2><table><tr><th>Case</th><th>Outcome</th><th>Detail</th></tr>{''.join(case_rows)}</table>
<h2>Benchmark</h2><pre>{benchmark_json}</pre>
<h2>Differential leakage</h2><p>Status: {html.escape(str(leakage.get('status', 'not_run')))}</p>{leakage_markup}
</body></html>"""


def render_privacy_section(privacy: dict[str, Any]) -> str:
    """Render only summarized evidence; never include raw trace or fixture objects."""
    esc = lambda value: html.escape(str(value), quote=True)
    findings = privacy.get('findings', [])
    cases = privacy.get('cases', [])
    controls = privacy.get('detector_controls', [])
    if isinstance(controls, dict):
        controls = controls.get('cases', [])
    gaps = [c for c in cases if c.get('status') in {'coverage_gap', 'not_run', 'inconclusive'} or c.get('skip_reason')]
    gap_reasons = {c.get('case_id'): c.get('reason') for c in privacy.get('coverage', {}).get('gaps', [])}
    rows = []
    for case in cases:
        if case.get('evidence_kind') == 'control':
            continue
        details = case.get('skip_reason') or case.get('reason') or gap_reasons.get(case.get('id')) or case.get('summary') or ''
        for finding in case.get('findings', []):
            details += ' ' + str(finding.get('detail', ''))
        rows.append('<tr>' + ''.join(f'<td>{esc(v)}</td>' for v in [
            case.get('id', ''), case.get('family', ''), case.get('observer', ''),
            case.get('runtime', ''), case.get('evidence_kind', ''),
            case.get('status', ''), details.strip()]) + '</tr>')
    finding_cards = ''.join(
        f'<article class="finding"><strong>{esc(f.get("kind", "Finding"))}</strong>'
        f'<p>{esc(f.get("detail", ""))}</p><small>Case: {esc(f.get("case_id", ""))} · '
        f'Observer: {esc(f.get("observer", ""))} · Path: {esc(f.get("field", ""))}</small></article>'
        for f in findings)
    control_rows = ''.join('<tr>' + ''.join(f'<td>{esc(v)}</td>' for v in [
        c.get('id', c.get('case_id', c.get('name', 'control'))),
        ('passed' if c.get('status') == c['expected_status'] else 'failed') if 'expected_status' in c else c.get('status', ''),
        c.get('expected_status', 'unspecified'), c.get('status', ''),
        c.get('summary', c.get('detail', 'Deliberately faulty or clean detector fixture'))]) + '</tr>'
        for c in controls)
    gap_rows = ''.join(f'<li><strong>{esc(c.get("id", ""))}</strong>: '
                       f'{esc(c.get("skip_reason") or c.get("reason") or gap_reasons.get(c.get("id")) or "Evidence is insufficient for a conclusion")}</li>'
                       for c in gaps)
    return f'''<div class="status">{esc(privacy.get('status', 'not_run')).replace('_', ' ').upper()}</div>
<p class="lead">{esc(privacy.get('summary', 'No campaign evidence supplied.'))}</p>
<div class="metrics"><div><b>{len(findings)}</b><span>Observed findings</span></div>
<div><b>{len(controls)}</b><span>Detector controls</span></div>
<div><b>{len(gaps)}</b><span>Coverage gaps</span></div></div>
<h2>Observed findings</h2>{finding_cards or '<p>No findings in the observed surfaces. See coverage before drawing conclusions.</p>'}
<h2>Executed scenarios and observations</h2><div class="scroll"><table><thead><tr>
<th>Scenario</th><th>Family</th><th>Observer</th><th>Runtime</th><th>Evidence</th><th>Result</th><th>Explanation</th>
</tr></thead><tbody>{''.join(rows)}</tbody></table></div>
<h2>Coverage gaps</h2><ul>{gap_rows or '<li>No declared scenario gaps.</li>'}</ul>
<h2>Detector controls</h2><p>These fixtures exercise the detectors. They are excluded from observed integration findings.</p>
<table><thead><tr><th>Control</th><th>Result</th><th>Expected observation</th><th>Actual observation</th><th>Purpose</th></tr></thead><tbody>{control_rows}</tbody></table>
<p class="note">Evidence is limited to the named observers and runtime. A clean observation does not establish cryptographic zero knowledge or unlinkability. Timing and size findings are exploratory signals.</p>'''


def render_privacy_report(report: dict[str, Any]) -> str:
    title = html.escape(str(report.get('provider', {}).get('title', 'Integration privacy campaign')))
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{title} · Privacy campaign</title>
<style>
:root{{color-scheme:light}}*{{box-sizing:border-box}}body{{margin:0;background:#f5f5f0;color:#202b30;font:15px/1.6 system-ui,sans-serif}}
main{{max-width:1260px;margin:0 auto;padding:44px 30px}}header{{border-bottom:2px solid #263e3b;padding-bottom:24px;margin-bottom:26px}}
.eyebrow{{font-size:12px;letter-spacing:.16em;font-weight:700;color:#4c6963}}h1{{font-size:34px;line-height:1.2;margin:12px 0}}
h2{{font-size:21px;margin-top:34px}}.lead{{max-width:900px;font-size:17px}}.status{{display:inline-block;background:#e8dec7;border:1px solid #ccbd9d;border-radius:5px;padding:4px 12px;font-size:13px;font-weight:700}}
.metrics{{display:flex;gap:18px;margin:25px 0}}.metrics div{{background:white;border:1px solid #d7deda;border-radius:8px;padding:18px 24px;flex:1}}
.metrics b{{display:block;font-size:30px}}.metrics span{{color:#55716a}}table{{border-collapse:collapse;width:100%;font-size:13px;background:white}}
th,td{{border-bottom:1px solid #d7deda;text-align:left;padding:12px;vertical-align:top;overflow-wrap:anywhere}}th{{background:#e7ece7}}
.scroll{{overflow:auto}}.finding{{background:#fff6e8;border-left:4px solid #b9652f;padding:14px 20px;margin:12px 0;overflow-wrap:anywhere}}
.finding p{{margin:6px 0}}small,.note{{color:#52635d}}.note{{margin-top:30px;border-top:1px solid #c7d1ca;padding-top:18px}}
@media(max-width:700px){{main{{padding:22px 14px}}h1{{font-size:26px}}.metrics{{gap:8px}}.metrics div{{padding:12px}}}}
</style></head><body><main><header><div class="eyebrow">SWIYU · INTEGRATION PRIVACY</div>
<h1>{title}</h1><p>Provider-neutral scenarios, observed boundaries, explicit coverage.</p></header>
{render_privacy_section(report.get('privacy', {}))}</main></body></html>'''
