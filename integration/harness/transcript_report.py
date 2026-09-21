"""Public, deliberately selected evidence from transcript campaigns."""
from html import escape
import json


def _text(value):
    return escape(str(value))


def _number(value):
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return f'{value:,.1f}' if isinstance(value, float) else f'{value:,}'
    return 'Not measured'


def _finding_location(finding):
    parts = []
    boundary = finding.get('boundary')
    if boundary not in (None, ''):
        parts.append(_text(boundary))
    pointers = finding.get('pointers')
    if isinstance(pointers, list):
        shown = [_text(item) for item in pointers if item not in (None, '')]
        if shown:
            parts.append(', '.join(shown))
    elif pointers not in (None, ''):
        fallback = finding.get('location', finding.get('pointer', finding.get('path', finding.get('field', ''))))
        if fallback not in (None, ''):
            parts.append(_text(fallback))
        else:
            parts.append(_text(pointers))
    else:
        fallback = finding.get('location', finding.get('pointer', finding.get('path', finding.get('field', ''))))
        if fallback not in (None, ''):
            parts.append(_text(fallback))
    return ' · '.join(parts)


def render_transcript_report(bundle):
    """Render sanitized campaign results; never serialize private session inputs."""
    campaigns = bundle.get('campaigns', [])
    sessions = bundle.get('sessions', [])
    cards = []
    for campaign in campaigns:
        report = campaign.get('report', {})
        findings = report.get('findings', [])
        pairs = report.get('pairs', [])
        status = report.get('status', 'inconclusive')
        rows = []
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            path = _finding_location(finding)
            rows.append('<li><strong>' + _text(finding.get('kind', finding.get('code', 'Finding'))) + '</strong><br><code>' + path + '</code><br>' + _text(finding.get('explanation', finding.get('detail', finding.get('message', '')))) + '</li>')
        evidence = '<ul class="findings">' + ''.join(rows) + '</ul>' if rows else ('<p>Transcript differences are shown in the pair comparisons below.</p>' if any(p.get('status') == 'mismatch' for p in pairs) else '<p>No findings in these observations.</p>')
        pair_html = ''
        if pairs:
            pair_html = '<details><summary>Pair comparisons (' + str(len(pairs)) + ')</summary><pre>' + _text(json.dumps(pairs, indent=2)) + '</pre></details>'
        cards.append(f'<article><div class="eyebrow">{_text(campaign.get("kind", "unspecified"))}</div><h2>{_text(campaign.get("name", "Campaign"))}</h2><span class="pill">{_text(status)}</span>{evidence}{pair_html}</article>')
    session_rows = ''.join('<tr>' + ''.join(f'<td>{value}</td>' for value in [
        _text(s.get('id', '')), _text(s.get('variant', '')),
        'Accepted' if s.get('accepted') is True else 'Rejected' if s.get('accepted') is False else 'Unknown',
        _number(s.get('event_count')), _number(s.get('proof_bytes')),
        _number(s.get('witness_bytes')), _number(s.get('prepare_ms')), _number(s.get('present_ms')), _number(s.get('post_ms')),
    ]) + '</tr>' for s in sessions)
    accepted = sum(s.get('accepted') is True for s in sessions)
    case_study = _text(bundle.get('case_study', 'The same approved claim is exercised with different hidden inputs. Each observed flow is checked against that semantic relation.'))
    novelty = _text(bundle.get('novelty', 'A reusable connection from pinned semantic claims and approved releases to differential checks over complete selected OID4VP flows, alongside real proof integration and benchmarks.'))
    scope = _text(bundle.get('qualification', 'Runtime scope not supplied.'))
    policy_detail = '<details><summary>Normalization policy and unassessed channels</summary><pre>' + _text(json.dumps({'policy': bundle.get('policy', {}), 'unassessed_channels': sorted({channel for c in campaigns for channel in c.get('report', {}).get('unassessed_channels', [])})}, indent=2)) + '</pre></details>' 
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Transcript privacy · {_text(bundle.get('provider', 'Provider'))}</title>
<style>
:root{{color-scheme:light;--ink:#17332f;--muted:#526862;--line:#d0ddd6;--paper:#f5f7f1;--accent:#006e59}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--paper);color:var(--ink);font:16px/1.6 system-ui,sans-serif}}main{{max-width:1160px;margin:auto;padding:48px 26px 80px}}header{{border-bottom:1px solid var(--line);padding-bottom:30px}}h1{{font-size:clamp(30px,5vw,54px);letter-spacing:-.045em;line-height:1.12;margin:12px 0 22px;max-width:850px}}h2{{font-size:23px;letter-spacing:-.02em;margin:7px 0 15px}}h3{{font-size:17px}}p{{max-width:920px}}.eyebrow{{text-transform:uppercase;font-size:12px;letter-spacing:.12em;font-weight:700;color:var(--accent)}}.sub{{color:var(--muted)}}.metrics{{display:flex;gap:40px;flex-wrap:wrap;margin:28px 0}}.metric strong{{display:block;font-size:35px;line-height:1.2}}.metric span{{font-size:13px;color:var(--muted)}}.flow{{display:flex;align-items:center;gap:10px;flex-wrap:wrap;background:#e5efe7;border:1px solid var(--line);border-radius:12px;padding:22px;margin:28px 0}}.flow span{{flex:1;min-width:160px}}.flow small{{display:block;color:var(--muted)}}.flow b{{color:var(--accent)}}.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:18px}}article{{background:white;border:1px solid var(--line);padding:25px;border-radius:12px;overflow:hidden}}.pill{{display:inline-block;font-size:12px;font-weight:700;padding:3px 9px;background:#e9eee4;border-radius:20px}}section{{margin-top:38px}}table{{border-collapse:collapse;width:100%;font-size:13px}}td,th{{padding:12px 10px;text-align:left;border-bottom:1px solid var(--line)}}th{{font-size:11px;text-transform:uppercase;letter-spacing:.06em}}.scroll{{overflow:auto}}code,pre{{font:12px/1.5 ui-monospace,monospace;overflow-wrap:anywhere;white-space:pre-wrap}}pre{{max-height:360px;overflow:auto}}.findings{{padding-left:20px}}.findings li{{margin-bottom:16px}}details{{margin-top:15px}}summary{{cursor:pointer;font-size:13px;font-weight:600}}.note{{border-left:3px solid var(--accent);padding-left:20px}}footer{{margin-top:40px;color:var(--muted);font-size:13px}}
</style></head><body><main><header><div class="eyebrow">Swiyu · Provider integration evidence</div><h1>Does a private proof stay private through the whole flow?</h1><p class="sub">{_text(bundle.get('provider', ''))} · {_text(bundle.get('claim', ''))}</p><p>{case_study}</p><div class="metrics"><div class="metric"><strong>{len(sessions)}</strong><span>observed sessions</span></div><div class="metric"><strong>{accepted}</strong><span>accepted presentations</span></div><div class="metric"><strong>{len(campaigns)}</strong><span>separate campaigns</span></div></div></header>
<div class="flow"><span><b>1 · Same permitted claim</b><small>Authenticate fixtures; vary hidden data</small></span><b>→</b><span><b>2 · Real presentation flow</b><small>Capture each selected HTTP exchange</small></span><b>→</b><span><b>3 · Compare observer views</b><small>Validate session bindings; retain extra data</small></span></div>
<section><h2>What this run actually exercised</h2><p class="note">{scope}</p>{policy_detail}</section><section class="cards">{''.join(cards)}</section>
<section><h2>Proof and flow evidence</h2><div class="scroll"><table><thead><tr><th>Session</th><th>Private variant</th><th>Verifier</th><th>Exchanges</th><th>Proof bytes (presentation leaf)</th><th>Witness bytes (provider-reported)</th><th>Prepare ms</th><th>Present ms</th><th>Submit + verify ms</th></tr></thead><tbody>{session_rows}</tbody></table></div><p class="sub">Submit + verify includes HTTP transport, Swiyu processing, and provider verification. Proof size is measured from the actual presentation leaf. Witness sizes are provider-reported. Times are observations on this laptop. These samples do not establish a timing distribution or phone performance.</p></section>
<section><h2>The contribution</h2><p>{novelty}</p><p>Finite tests can expose a violation of the declared privacy relation. A passing campaign does not prove cryptographic zero knowledge, circuit correctness, or universal unlinkability. Proof contents remain an audit obligation; their observable lengths remain part of the comparison.</p></section><footer>Baseline observations and injected regressions are labeled separately. Observer scope and normalization exceptions define what this report can establish.</footer></main></body></html>'''
