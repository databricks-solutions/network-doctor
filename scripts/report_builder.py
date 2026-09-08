"""HTML dashboard report builder for the Network Connectivity Doctor.

Importable module: sibling scripts resolve via sys.path (the skill dir is
inserted by SKILL.md Step 1). Also works exec-loaded for back-compat.
"""

import html as html_module
import re as _re

from models import (CheckResult, Diagnosis, DiagnosticReport, Severity, Status,
                    __version__, actionable_diagnoses, check_verdict_counts,
                    headline_words, is_unverified_skip, limitations_items,
                    merge_gate_skips, report_rows, split_skipped_rows,
                    unverified_layer_items, worst_status)


def _esc(t):
    return html_module.escape(str(t))


def _md_to_html(md_text):
    """Convert markdown to styled HTML for the diagnosis card."""
    lines = md_text.split("\n")
    html_lines = []
    in_table = False
    in_list = False
    table_rows = []

    for line in lines:
        stripped = line.strip()

        if stripped in ("---", "***", "___"):
            continue

        if stripped.startswith("# "):
            continue
        if stripped.startswith("## "):
            if in_list:
                html_lines.append("</ul>")
                in_list = False
            title = stripped[3:].strip()
            num_match = _re.match(r"(\d+)\.\s*(.*)", title)
            if num_match:
                num, title_text = num_match.groups()
                html_lines.append(
                    f'<div style="margin-top:24px;margin-bottom:12px;display:flex;align-items:center;gap:10px;">'
                    f'<span style="background:linear-gradient(135deg,#4a0e8f,#7b2ff7);color:#fff;'
                    f'width:32px;height:32px;border-radius:50%;display:flex;align-items:center;'
                    f'justify-content:center;font-weight:bold;font-size:0.9em;flex-shrink:0;">{num}</span>'
                    f'<span style="font-size:1.15em;font-weight:700;color:#1b3a4b;">{_esc(title_text)}</span></div>')
            else:
                html_lines.append(
                    f'<div style="margin-top:24px;margin-bottom:12px;font-size:1.15em;'
                    f'font-weight:700;color:#1b3a4b;border-bottom:2px solid #e0e0e0;padding-bottom:6px;">'
                    f'{_esc(title)}</div>')
            continue
        if stripped.startswith("### "):
            if in_list:
                html_lines.append("</ul>")
                in_list = False
            title = stripped[4:].strip()
            html_lines.append(
                f'<div style="margin-top:18px;margin-bottom:8px;font-size:1em;'
                f'font-weight:600;color:#2d5f7b;">{_esc(title)}</div>')
            continue

        if "|" in stripped and stripped.startswith("|"):
            cells = [c.strip() for c in stripped.split("|")[1:-1]]
            if all(_re.match(r"^[-:]+$", c) for c in cells):
                continue
            if not in_table:
                in_table = True
                table_rows = []
                header_cells = "".join(
                    f'<th style="padding:10px 14px;text-align:left;background:#1b3a4b;color:#fff;'
                    f'font-size:0.82em;font-weight:600;border:1px solid #dee2e6;">{_esc(c)}</th>'
                    for c in cells)
                table_rows.append(f"<tr>{header_cells}</tr>")
            else:
                row_style = ""
                row_text = " ".join(cells).lower()
                if "fail" in row_text or "error" in row_text:
                    row_style = "background:#f8d7da;"
                elif "pass" in row_text:
                    row_style = "background:#d4edda;"
                elif "warn" in row_text or "skip" in row_text:
                    row_style = "background:#fff3cd;"
                else:
                    row_style = "background:#fff;"
                data_cells = "".join(
                    f'<td style="padding:8px 14px;border:1px solid #dee2e6;font-size:0.85em;">{_esc(c)}</td>'
                    for c in cells)
                table_rows.append(f'<tr style="{row_style}">{data_cells}</tr>')
            continue
        elif in_table:
            html_lines.append(
                '<table style="width:100%;border-collapse:collapse;margin:12px 0;border-radius:6px;overflow:hidden;">'
                + "".join(table_rows) + "</table>")
            in_table = False
            table_rows = []

        num_list = _re.match(r"^(\d+)\.\s+(.*)", stripped)
        if num_list:
            if in_list:
                html_lines.append("</ul>")
                in_list = False
            num, content = num_list.groups()
            content = _re.sub(r"\*\*(.*?)\*\*", r"<strong>\1</strong>", content)
            content = _re.sub(r"`(.*?)`", r'<code style="background:#f0f0f0;padding:1px 5px;border-radius:3px;font-size:0.9em;">\1</code>', content)
            html_lines.append(
                f'<div style="display:flex;gap:10px;align-items:flex-start;margin:8px 0;'
                f'padding:10px 14px;background:#f8f9fa;border-radius:6px;border-left:3px solid #7b2ff7;">'
                f'<span style="background:#7b2ff7;color:#fff;min-width:24px;height:24px;border-radius:50%;'
                f'display:flex;align-items:center;justify-content:center;font-size:0.8em;font-weight:bold;flex-shrink:0;">{num}</span>'
                f'<div style="font-size:0.9em;line-height:1.6;">{content}</div></div>')
            continue

        if stripped.startswith("- ") or stripped.startswith("* "):
            content = stripped[2:]
            content = _re.sub(r"\*\*(.*?)\*\*", r"<strong>\1</strong>", content)
            content = _re.sub(r"`(.*?)`", r'<code style="background:#f0f0f0;padding:1px 5px;border-radius:3px;font-size:0.9em;">\1</code>', content)
            if not in_list:
                html_lines.append('<ul style="margin:8px 0;padding-left:0;list-style:none;">')
                in_list = True
            html_lines.append(
                f'<li style="padding:6px 12px;margin:4px 0;font-size:0.88em;line-height:1.5;'
                f'border-left:2px solid #ddd;margin-left:8px;">{content}</li>')
            continue
        elif in_list and stripped:
            html_lines.append("</ul>")
            in_list = False

        if stripped:
            para = _esc(stripped)
            para = _re.sub(r"\*\*(.*?)\*\*", r"<strong>\1</strong>", para)
            para = _re.sub(r"`(.*?)`", r'<code style="background:#f0f0f0;padding:1px 5px;border-radius:3px;font-size:0.9em;">\1</code>', para)
            html_lines.append(f'<p style="margin:8px 0;font-size:0.9em;line-height:1.7;color:#333;">{para}</p>')

    if in_table:
        html_lines.append(
            '<table style="width:100%;border-collapse:collapse;margin:12px 0;">'
            + "".join(table_rows) + "</table>")
    if in_list:
        html_lines.append("</ul>")

    return "\n".join(html_lines)


def build_dashboard(reports, ai_diagnosis, problem_text, timestamp):
    """Build the HTML diagnostic dashboard.

    Args:
        reports: list of dicts with keys: name, host, port, checks (list of CheckResult),
                 overall (Status), connection_type (str)
        ai_diagnosis: markdown string with the physician's analysis
        problem_text: the original problem description
        timestamp: string timestamp of the diagnostic run

    Returns:
        HTML string ready for displayHTML()
    """
    total_targets = len(reports)

    # the tiles used to count TARGETS while their labels ("Healthy", "Warnings")
    # read as a summary of the CHECK ROWS below them. With one target whose overall was
    # FAIL that produced "1 Targets Tested | 0 Healthy | 0 Warnings" on a report showing
    # three visibly WARN rows. A summary that contradicts the thing it summarises is worse
    # than no summary, so count the rows.
    all_checks = [c for r in reports for c in (r.get("checks") or [])]

    def _n(*statuses):
        return sum(1 for c in all_checks if getattr(c, "status", None) in statuses)

    passed = _n(Status.PASS)
    failed = _n(Status.FAIL, Status.ERROR)
    warnings = _n(Status.WARN)
    skipped = _n(Status.SKIP)

    # the banner used to be recomputed from the ROWS (`failed > 0` ->
    # "ISSUES DETECTED"), independently of report.overall_status. That is how a healthy
    # workspace whose only finding was a MEDIUM "latent — not blocking this target"
    # diagnosis got a red ISSUES DETECTED banner. The banner now RENDERS the verdict
    # the report already reached (models.derive_overall_status); the tiles keep counting
    # rows, which is the row-level truth and must stay visible.
    # Under-counted gaps on the dashboard. It is the artefact people forward, and it
    # carried NO number for unverified layers: the tile said "11 Skipped" and the customer
    # said "if someone forwarded me only the dashboard PNG I'd read the gap as either 0 or
    # 11, never 2". The banner does print the gap count — but only on the `pass` branch,
    # and this run was `warn` because of one unrelated row, so the number appeared nowhere.
    # The tile is therefore the right home: it is next to the count it must not be
    # confused with, and it is independent of the verdict branch.
    _counts = check_verdict_counts(all_checks)
    _gaps = _counts["unverified"]
    unverified_tile_note = (
        f'<div style="margin-top:8px;padding-top:8px;border-top:1px solid #e9ecef;'
        f'font-size:0.82em;color:#856404;font-weight:600;">{_gaps} unverified '
        f'&mdash; {"a real gap" if _gaps == 1 else "real gaps"}</div>'
        if _gaps else
        '<div style="margin-top:8px;padding-top:8px;border-top:1px solid #e9ecef;'
        'font-size:0.82em;color:#28a745;font-weight:600;">0 unverified</div>')

    worst = worst_status([r.get("overall") for r in reports])
    # D3 — the banner's qualifier must count UNVERIFIED rows (real gaps), not the raw
    # skip total. This call used to hand over {"skip": skipped}, which on an all-pass
    # serverless run would have read "HEALTHY — 10 NOT CHECKED" for ONE gap plus nine
    # declared not-applicable layers. Route through check_verdict_counts so the banner
    # and the chat headline read the SAME arithmetic and cannot drift; the tiles below
    # keep counting rows, which is the row-level truth and must stay visible.
    overall_text, overall_bg = headline_words(worst, check_verdict_counts(all_checks))

    status_bg = {"pass": "#28a745", "fail": "#dc3545", "warn": "#ffc107", "skip": "#6c757d", "error": "#dc3545"}
    status_fg = {"pass": "#fff", "fail": "#fff", "warn": "#212529", "skip": "#fff", "error": "#fff"}
    row_bg = {"pass": "#d4edda", "fail": "#f8d7da", "warn": "#fff3cd", "skip": "#e9ecef", "error": "#f8d7da"}

    def badge(s, large=False):
        bg = status_bg[s.value]
        fg = status_fg[s.value]
        sz = "font-size:1.1em;padding:6px 16px;" if large else "font-size:0.8em;padding:3px 10px;"
        return f'<span style="background:{bg};color:{fg};{sz}border-radius:4px;font-weight:bold;">{s.value.upper()}</span>'

    def row_badge(c):
        """The badge for one check row — with UNVERIFIED split out from SKIP.

        a gap camouflaged as a benign row, and it is the mirror image of the bug above.
        Reclassifying the account 403 from ERROR to a gap removed the "reads as no NCC
        attached" misreading and created the opposite one: the tester's words were "SKIP
        plus a 'Skipped: 11' tile reads as routine, nothing to see, and the NOT-READ row
        is buried among 8 genuinely not-applicable classic-plane skips carrying
        identical-looking badges."

        A gap and a not-applicable layer are DIFFERENT FACTS. They had the same grey
        badge, so the table asserted, visually, that they were the same kind of thing.
        Amber and the word UNVERIFIED for a gap; a muted N/A for a declared skip, which
        is genuinely housekeeping. Same vocabulary as the limits block and the chat, so
        one glance at any surface finds the same set.
        """
        if getattr(c, "status", None) is Status.SKIP:
            if is_unverified_skip(c):
                return ('<span style="background:#fff3cd;color:#856404;border:2px solid #856404;'
                        'font-size:0.8em;padding:2px 9px;border-radius:4px;font-weight:bold;">'
                        'UNVERIFIED</span>')
            return ('<span style="background:#e9ecef;color:#6c757d;border:1px solid #ced4da;'
                    'font-size:0.8em;padding:3px 10px;border-radius:4px;font-weight:600;">'
                    'N/A</span>')
        # `badge` takes a Status, not a row. Passing the row raised AttributeError on the
        # FIRST non-skip row, i.e. it broke the whole dashboard rather than one cell —
        # caught by the offline exercise, which is the only reason it is not a live defect.
        return badge(c.status)

    header = f'''
    <div style="background:linear-gradient(135deg, #1b3a4b 0%, #2d5f7b 100%);color:#fff;padding:30px 40px;border-radius:8px 8px 0 0;">
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <div>
          <h1 style="margin:0;font-size:1.8em;letter-spacing:0.5px;">Network Connectivity Doctor</h1>
          <p style="margin:8px 0 0;opacity:0.8;font-size:0.9em;">Patient complaint: <em>{_esc(problem_text[:150])}</em></p>
        </div>
        <div style="text-align:right;">
          <div style="background:{overall_bg};color:#fff;padding:12px 24px;border-radius:6px;font-size:1.3em;font-weight:bold;">
            {overall_text}
          </div>
          <p style="margin:8px 0 0;opacity:0.7;font-size:0.85em;">{_esc(timestamp)}</p>
        </div>
      </div>
    </div>'''

    cards = f'''
    <div style="display:flex;gap:16px;padding:20px 40px;background:#f8f9fa;border-bottom:1px solid #dee2e6;">
      <div style="flex:1;background:#fff;border-radius:8px;padding:20px;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,0.1);">
        <div style="font-size:2.5em;font-weight:bold;color:#1b3a4b;">{total_targets}</div>
        <div style="font-size:0.9em;color:#666;margin-top:4px;">Targets Tested</div>
      </div>
      <div style="flex:1;background:#fff;border-radius:8px;padding:20px;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,0.1);">
        <div style="font-size:2.5em;font-weight:bold;color:#28a745;">{passed}</div>
        <div style="font-size:0.9em;color:#666;margin-top:4px;">Checks Passed</div>
      </div>
      <div style="flex:1;background:#fff;border-radius:8px;padding:20px;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,0.1);">
        <div style="font-size:2.5em;font-weight:bold;color:#dc3545;">{failed}</div>
        <div style="font-size:0.9em;color:#666;margin-top:4px;">Issues Found</div>
      </div>
      <div style="flex:1;background:#fff;border-radius:8px;padding:20px;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,0.1);">
        <div style="font-size:2.5em;font-weight:bold;color:#ffc107;">{warnings}</div>
        <div style="font-size:0.9em;color:#666;margin-top:4px;">Warnings</div>
      </div>
      <div style="flex:1;background:#fff;border-radius:8px;padding:20px;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,0.1);">
        <div style="font-size:2.5em;font-weight:bold;color:#6c757d;">{skipped}</div>
        <div style="font-size:0.9em;color:#666;margin-top:4px;">Skipped</div>
        {unverified_tile_note}
      </div>
    </div>'''

    diagnosis_html = ""
    if ai_diagnosis:
        formatted = _md_to_html(ai_diagnosis)
        diagnosis_html = f'''
    <div style="margin:20px 40px;background:#fff;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,0.08);overflow:hidden;">
      <div style="padding:18px 24px;background:linear-gradient(135deg,#4a0e8f 0%,#7b2ff7 100%);color:#fff;display:flex;align-items:center;gap:14px;">
        <span style="font-size:2em;">&#129658;</span>
        <div>
          <h3 style="margin:0;font-size:1.2em;font-weight:700;">AI Physician Diagnosis</h3>
          <p style="margin:4px 0 0;opacity:0.7;font-size:0.78em;">Powered by Genie Code</p>
        </div>
      </div>
      <div style="padding:24px 28px;">{formatted}</div>
    </div>'''

    target_cards = ""
    for r in reports:
        check_rows = ""
        for c in r["checks"]:
            bg = row_bg[c.status.value]
            if c.status is Status.SKIP and is_unverified_skip(c):
                # Tinted like a warning, because that is what an unsettled layer is. The
                # row must not be visually interchangeable with the eight beside it that
                # correctly do not apply.
                bg = "#fffbf0"
            dur = f"{c.duration_ms:.0f}ms" if c.duration_ms > 0 else "--"
            # WHICH NETWORK was measured. A probe measures the network of the machine that
            # ran it, so on a classic diagnosis this is the difference between an answer and
            # a wrong answer — and it was recorded in the JSON only, invisible to anyone
            # checking the diagnosis by hand in the artefact they actually forward.
            _md = getattr(c, "metadata", None) or {}
            _loc = str(_md.get("execution_location") or "").strip()
            if _loc == "remote_classic_cluster":
                _cid = str(_md.get("execution_cluster_id") or "").strip()
                where = "your cluster" + (f" {_cid}" if _cid else "")
                if _md.get("probe_plane_confirmed"):
                    where += " (in-VNet, confirmed)"
            elif _loc:
                where = _loc.replace("_", " ")
            else:
                where = "--"
            raw_section = ""
            if c.raw_output:
                raw_section = (
                    '<details style="margin-top:6px;">'
                    '<summary style="cursor:pointer;color:#555;font-size:0.82em;">Show raw output</summary>'
                    f'<pre style="background:#f5f5f5;padding:8px;border-radius:3px;font-size:0.78em;'
                    f'max-height:200px;overflow:auto;margin-top:4px;">{_esc(c.raw_output)}</pre></details>')
            check_rows += f'''
            <tr style="background:{bg};">
              <td style="padding:10px 14px;border-bottom:1px solid #dee2e6;font-weight:500;">{_esc(c.check_name)}</td>
              <td style="padding:10px 14px;border-bottom:1px solid #dee2e6;text-align:center;">{row_badge(c)}</td>
              <td style="padding:10px 14px;border-bottom:1px solid #dee2e6;text-align:right;font-family:monospace;font-size:0.85em;">{dur}</td>
              <td style="padding:10px 14px;border-bottom:1px solid #dee2e6;font-size:0.82em;color:#555;">{_esc(where)}</td>
              <td style="padding:10px 14px;border-bottom:1px solid #dee2e6;font-size:0.9em;">{_esc(c.message)}{raw_section}</td>
            </tr>'''

        recs_html = ""
        failed_checks = [c for c in r["checks"] if c.is_failure() and c.recommendation]
        if failed_checks:
            rec_items = "".join(f'''
                <div style="background:#fff;border-left:4px solid #dc3545;padding:12px 16px;margin-bottom:10px;border-radius:0 4px 4px 0;">
                  <strong style="color:#dc3545;">{_esc(c.check_name)}</strong>
                  <pre style="margin:8px 0 0;white-space:pre-wrap;font-size:0.85em;color:#333;font-family:inherit;">{_esc(c.recommendation)}</pre>
                </div>''' for c in failed_checks)
            recs_html = f'''
            <div style="margin-top:16px;padding:16px;background:#fff3cd;border-radius:6px;">
              <h4 style="margin:0 0 12px;color:#856404;font-size:0.95em;">Quick Fix Checklist</h4>
              {rec_items}
            </div>'''

        overall_icon = "&#9989;" if r["overall"] == Status.PASS else ("&#10060;" if r["overall"] == Status.FAIL else "&#9888;&#65039;")
        card_bg = '#d4edda' if r['overall']==Status.PASS else '#f8d7da' if r['overall']==Status.FAIL else '#fff3cd'

        target_cards += f'''
        <div style="margin:20px 40px;background:#fff;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,0.08);overflow:hidden;">
          <div style="padding:18px 24px;background:{card_bg};border-bottom:1px solid #dee2e6;display:flex;justify-content:space-between;align-items:center;">
            <div>
              <h3 style="margin:0;font-size:1.15em;color:#1b3a4b;">{overall_icon} {_esc(r['name'])}</h3>
              <span style="font-size:0.85em;color:#555;font-family:monospace;">{_esc(r['host'])}:{r['port']} [{_esc(r.get('connection_type',''))}]</span>
            </div>
            {badge(r['overall'], large=True)}
          </div>
          <div style="padding:16px 24px;">
            <table style="width:100%;border-collapse:collapse;">
              <thead><tr style="background:#1b3a4b;color:#fff;">
                <th style="padding:10px 14px;text-align:left;width:18%;font-size:0.85em;">Check</th>
                <th style="padding:10px 14px;text-align:center;width:10%;font-size:0.85em;">Status</th>
                <th style="padding:10px 14px;text-align:right;width:8%;font-size:0.85em;">Duration</th>
                <th style="padding:10px 14px;text-align:left;width:16%;font-size:0.85em;">Measured on</th>
                <th style="padding:10px 14px;text-align:left;width:48%;font-size:0.85em;">Details</th>
              </tr></thead>
              <tbody>{check_rows}</tbody>
            </table>
            {recs_html}
          </div>
        </div>'''

    footer = f'''
    <div style="padding:16px 40px;background:#f8f9fa;border-top:1px solid #dee2e6;border-radius:0 0 8px 8px;
                text-align:center;font-size:0.8em;color:#6c757d;">
      Network Connectivity Doctor v{_esc(__version__)} &nbsp;|&nbsp; {_esc(timestamp)}
    </div>'''

    return f'''<div style="font-family:'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;max-width:1000px;margin:0 auto;
                border:1px solid #dee2e6;border-radius:8px;overflow:hidden;background:#f0f2f5;">
    {header}{cards}{diagnosis_html}{target_cards}{footer}</div>'''


def _limits_panel(diagnostic_reports):
    """The "Limits of this diagnosis" section, rendered into the DASHBOARD.

    The dashboard had none of it. Grep of the rendered page on the live
    serverless-healthy run: 0 hits for "limits of this diagnosis", "unverified" and
    "not checked", while the same run's chat named nine layers. The customer said the
    dashboard "is the artefact I'd forward to my platform team, and it is markedly more
    reassuring than the chat — `Skipped: 9` beside `Checks Passed: 6` reads as
    housekeeping, not as a gap", and graded PARTLY VERIFIED from the chat but VERIFIED
    from the dashboard alone. A deliverable that is more reassuring than the truth is
    the defect, and this is the copy that gets forwarded.

    Composed by models.limitations_items — the SAME function the chat uses — so the two
    surfaces cannot say different things about the same run.
    """
    sections, any_gap, gap_total = [], False, 0
    for dr in diagnostic_reports or []:
        items, gaps = limitations_items(dr)
        if not items:
            continue
        any_gap = any_gap or bool(gaps)
        unver, _declared = split_skipped_rows(dr)
        gap_total += len(unver)
        head = ""
        if len(diagnostic_reports) > 1:
            head = (f'<div style="font-weight:600;color:#1b3a4b;font-size:0.9em;margin:10px 0 2px;">'
                    f'{_esc(dr.target)}</div>')
        sections.append(head + _md_to_html("\n".join(items)))
    if not sections:
        return ""
    # Amber and named as a GAP when something could not be settled; neutral grey when
    # the only content is declared not-applicable scope. The heading must not overstate
    # in either direction — that symmetry is the whole point of the split.
    if any_gap:
        bar, bg, fg = "#856404", "#fff3cd", "#856404"
        # The NUMBER, in the heading, next to the rows it counts (item 4, second half).
        # "2" appeared nowhere on the dashboard: the tile said 11 Skipped and the banner's
        # gap count only prints on the `pass` branch. The panel already NAMED both rows —
        # but a forwarded artefact is skimmed by headings, and a heading that says "some
        # layers" leaves the reader to count. State it where it is named, and match the
        # tile's wording so the two cannot be read as different facts.
        _n = gap_total or len(gaps)
        title = (f"Limits of this diagnosis &mdash; {_n} layer{'' if _n == 1 else 's'} this "
                 f"run could NOT settle")
        sub = (f"Read this before treating the report above as a clean result. The "
               f"&ldquo;Skipped&rdquo; count above includes layers that simply do not apply "
               f"here; these {_n} are the real gaps, and nothing in this report covers them.")
    else:
        bar, bg, fg = "#6c757d", "#e9ecef", "#343a40"
        title = "Scope of this diagnosis &mdash; what did not apply, and why"
        sub = "Nothing was left unsettled. These checks did not run because they do not apply."
    return f'''
        <div style="margin:20px 40px;background:#fff;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,0.08);overflow:hidden;border-left:5px solid {bar};">
          <div style="padding:16px 24px;background:{bg};color:{fg};">
            <h3 style="margin:0;font-size:1.1em;font-weight:700;">{title}</h3>
            <p style="margin:4px 0 0;font-size:0.8em;opacity:0.9;">{sub}</p>
          </div>
          <div style="padding:16px 24px;">{"".join(sections)}</div>
        </div>'''


def build_dashboard_v2(diagnostic_reports, problem_text, timestamp):
    """Build HTML dashboard from DiagnosticReport objects.

    Args:
        diagnostic_reports: list of DiagnosticReport objects
        problem_text: the original problem description
        timestamp: string timestamp

    Returns:
        HTML string ready for displayHTML()
    """
    severity_color = {
        "critical": ("#dc3545", "#fff"),
        "high": ("#fd7e14", "#fff"),
        "medium": ("#ffc107", "#212529"),
        "low": ("#17a2b8", "#fff"),
        "info": ("#28a745", "#fff"),
    }

    # Convert DiagnosticReports to old-style reports for base dashboard
    old_reports = []
    all_diagnoses = []
    for dr in diagnostic_reports:
        # Every row the customer can read, gate skips included. This used to
        # read `dr.checks` directly, which on an ARM-blind run held 7 rows while 11
        # checks had been skipped: the "Skipped" tile rendered 0 and, because
        # headline_words suppresses its qualifier at zero, the banner was free to say
        # ALL HEALTHY. `report_rows` also heals a report saved by an older build rather
        # than silently under-counting it.
        checks_list = list(report_rows(dr).values())
        old_reports.append({
            "name": dr.target,
            "host": dr.host,
            "port": dr.port,
            "checks": checks_list,
            "overall": dr.overall_status,
            "connection_type": "",
        })
        all_diagnoses.extend(dr.diagnoses)

    # Build diagnosis cards HTML.
    # the card list used to be "everything that is not INFO", and the header counted
    # it as "N issue(s) found". A card whose own content says "this configuration is
    # correct, change nothing" was therefore badged HIGH and counted as a second issue on
    # a run that had exactly one. Issue cards now come from the single shared definition
    # (models.actionable_diagnoses, which excludes INFO), and everything else renders in a
    # neutral CONTEXT section — visible, because "do not touch this" and "here is what I
    # could not verify" are useful, but never counted or coloured as a problem.
    actionable = actionable_diagnoses(all_diagnoses)
    context_diags = [d for d in all_diagnoses if d not in actionable]

    def _diag_card(d, muted=False):
        bg, fg = severity_color.get(d.severity.value, ("#6c757d", "#fff"))
        if muted:
            bg, fg = "#6c757d", "#fff"
        sev_badge = (
            f'<span style="background:{bg};color:{fg};padding:3px 10px;border-radius:4px;'
            f'font-size:0.8em;font-weight:bold;">'
            + ("NO ACTION NEEDED" if muted else d.severity.value.upper()) + '</span>'
        )
        conf_label = f'<span style="color:#666;font-size:0.8em;margin-left:8px;">Confidence: {d.confidence}</span>'

        needs_confirm = getattr(d, "needs_confirmation", False)
        confirm_badge = ""
        if needs_confirm:
            confirm_badge = (
                '<span style="background:#856404;color:#fff;padding:3px 10px;border-radius:4px;'
                'font-size:0.8em;font-weight:bold;margin-left:8px;">NEEDS CONFIRMATION</span>'
            )

        body = f'<p style="margin:8px 0;font-size:0.9em;color:#333;">{_esc(d.root_cause)}</p>'

        if needs_confirm:
            body += (
                '<p style="margin:8px 0;font-size:0.85em;color:#856404;font-style:italic;">'
                'This is a hypothesis pending your confirmation, not a confirmed root cause. '
                'Answer the question(s) below before applying any fix.</p>'
            )

        if d.prescription:
            steps = "".join(
                f'<li style="margin:4px 0;font-size:0.85em;">{_esc(s)}</li>'
                for s in d.prescription
            )
            presc_label = ("What to do about it: nothing — for reference:" if muted else
                           "Fix (only after the above is confirmed):" if needs_confirm else
                           "Prescription:")
            body += f'<div style="margin-top:8px;"><strong style="color:#155724;font-size:0.85em;">{presc_label}</strong><ol style="margin:4px 0 0 16px;">{steps}</ol></div>'

        if d.follow_up_questions:
            qs = "".join(
                f'<li style="margin:4px 0;font-size:0.85em;color:#856404;">{_esc(q)}</li>'
                for q in d.follow_up_questions
            )
            fu_label = "Confirm before this can be a root cause:" if needs_confirm else "Follow-up needed:"
            body += f'<div style="margin-top:8px;"><strong style="color:#856404;font-size:0.85em;">{fu_label}</strong><ul style="margin:4px 0 0 16px;">{qs}</ul></div>'

        marker = "&bull;" if muted else str(d.fix_order)
        return f'''
            <div style="background:#fff;border-left:4px solid {bg};padding:16px 20px;margin-bottom:12px;border-radius:0 6px 6px 0;box-shadow:0 1px 3px rgba(0,0,0,0.06);">
              <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">
                <span style="background:{bg};color:{fg};width:28px;height:28px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:bold;font-size:0.85em;flex-shrink:0;">{marker}</span>
                <strong style="font-size:1em;color:#1b3a4b;">{_esc(d.title)}</strong>
                {sev_badge}{confirm_badge}{conf_label}
              </div>
              {body}
            </div>'''

    diag_cards = ""
    if actionable:
        diag_cards += f'''
        <div style="margin:20px 40px;background:#fff;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,0.08);overflow:hidden;">
          <div style="padding:18px 24px;background:linear-gradient(135deg,#4a0e8f 0%,#7b2ff7 100%);color:#fff;">
            <h3 style="margin:0;font-size:1.2em;font-weight:700;">Diagnosis &amp; Fix Order</h3>
            <p style="margin:4px 0 0;opacity:0.7;font-size:0.78em;">{len(actionable)} issue(s) found &mdash; fix in order shown</p>
          </div>
          <div style="padding:20px 24px;">{"".join(_diag_card(d) for d in actionable)}</div>
        </div>'''
    # Order mirrors the chat guide: what to DO, then the limits, then the
    # no-action context. If a reader stops early they lose the cheapest thing, not the
    # most expensive — and the limits are never below the "no action needed" notes.
    diag_cards += _limits_panel(diagnostic_reports)
    if context_diags:
        diag_cards += f'''
        <div style="margin:20px 40px;background:#fff;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,0.08);overflow:hidden;">
          <div style="padding:18px 24px;background:#e9ecef;color:#343a40;">
            <h3 style="margin:0;font-size:1.05em;font-weight:700;">Context &amp; limits &mdash; no action required</h3>
            <p style="margin:4px 0 0;opacity:0.8;font-size:0.78em;">{len(context_diags)} note(s). These are NOT issues: correct settings you should leave alone, and layers this run could not verify.</p>
          </div>
          <div style="padding:20px 24px;">{"".join(_diag_card(d, muted=True) for d in context_diags)}</div>
        </div>'''

    # Build summary
    summary_text = ""
    if diagnostic_reports:
        summary_text = diagnostic_reports[0].summary
        if len(diagnostic_reports) > 1:
            summary_text = ". ".join(dr.summary for dr in diagnostic_reports if dr.summary)

    ai_diagnosis = summary_text if summary_text else ""

    # The old `if not diag_cards` branch did a .replace() on a marker string that
    # never occurs in the rendered page, so it was a no-op returning the base dashboard.
    # Say that plainly instead — and it matters more now, because `diag_cards` also
    # carries the limits panel and must not depend on a diagnosis existing.
    if not diag_cards:
        return build_dashboard(old_reports, ai_diagnosis, problem_text, timestamp)
    return _build_dashboard_v2_full(
        old_reports, diag_cards, ai_diagnosis, problem_text, timestamp)


def _build_dashboard_v2_full(old_reports, diag_cards, ai_diagnosis, problem_text, timestamp):
    """Internal: build full v2 dashboard with diagnosis cards before target cards."""
    # Re-use build_dashboard but inject diag_cards after summary cards
    base = build_dashboard(old_reports, ai_diagnosis, problem_text, timestamp)
    # Insert diagnosis cards before the AI Physician section or target cards
    marker = "AI Physician Diagnosis"
    if marker in base:
        idx = base.find(marker)
        # Find the parent div start (go back to find the div)
        div_start = base.rfind('<div style="margin:20px 40px', 0, idx)
        if div_start > 0:
            return base[:div_start] + diag_cards + base[div_start:]
    # Fallback: insert after summary cards section
    marker2 = "Quick Fix Checklist"
    marker3 = "</div>\n    </div>"
    # Just prepend diag_cards before target cards
    # Find end of summary cards (the flex row)
    cards_end = base.find("Warnings</div>")
    if cards_end > 0:
        # Find the closing div of the cards section
        next_div_end = base.find("</div>\n    </div>", cards_end)
        if next_div_end > 0:
            insert_at = next_div_end + len("</div>\n    </div>")
            return base[:insert_at] + diag_cards + base[insert_at:]
    # Ultimate fallback: just prepend
    return diag_cards + base


def _default_report_dir():
    """Resolve /Workspace/Users/<current_user>/network_doctor_reports."""
    import os
    user = ""
    try:
        from pyspark.sql import SparkSession
        spark = SparkSession.builder.getOrCreate()
        user = spark.sql("SELECT current_user()").collect()[0][0]
    except Exception:
        user = os.environ.get("USER") or "shared"
    return f"/Workspace/Users/{user}/network_doctor_reports"


def _report_path_stem(report=None, base_dir=None):
    """Build a stable path stem like <dir>/<target>_<ts> (no extension)."""
    import os
    from datetime import datetime, timezone

    if base_dir is None:
        base_dir = _default_report_dir()
    os.makedirs(base_dir, exist_ok=True)

    prefix = "dashboard"
    if report is not None:
        raw = getattr(report, "target", None) or getattr(report, "host", None) or ""
        cleaned = "".join(c if c.isalnum() or c in ("-", "_", ".") else "_" for c in str(raw))[:80]
        if cleaned:
            prefix = cleaned

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return os.path.join(base_dir, f"{prefix}_{stamp}")


def _check_to_dict(c):
    return {
        "check_name": getattr(c, "check_name", ""),
        "target": getattr(c, "target", ""),
        "status": getattr(getattr(c, "status", None), "value", str(getattr(c, "status", ""))),
        "message": getattr(c, "message", ""),
        "recommendation": getattr(c, "recommendation", ""),
        "raw_output": getattr(c, "raw_output", ""),
        "duration_ms": getattr(c, "duration_ms", 0.0),
        "metadata": getattr(c, "metadata", {}) or {},
    }


def check_to_dict(c):
    """Public single-CheckResult serializer (used by the orchestrator's checkpoints)."""
    return _check_to_dict(c)


def check_from_dict(c):
    """Public single-CheckResult deserializer (inverse of check_to_dict)."""
    try:
        status = Status(c.get("status", "pass"))
    except Exception:
        status = c.get("status", "pass")
    return CheckResult(
        check_name=c.get("check_name", ""),
        target=c.get("target", ""),
        status=status,
        message=c.get("message", ""),
        recommendation=c.get("recommendation", ""),
        raw_output=c.get("raw_output", ""),
        duration_ms=c.get("duration_ms", 0.0),
        metadata=c.get("metadata", {}) or {},
    )


def _diagnosis_to_dict(d):
    return {
        "pattern_id": getattr(d, "pattern_id", ""),
        "title": getattr(d, "title", ""),
        "severity": getattr(getattr(d, "severity", None), "value", str(getattr(d, "severity", ""))),
        "confidence": getattr(d, "confidence", ""),
        "root_cause": getattr(d, "root_cause", ""),
        "evidence": getattr(d, "evidence", []) or [],
        "prescription": getattr(d, "prescription", []) or [],
        "follow_up_questions": getattr(d, "follow_up_questions", []) or [],
        "fix_order": getattr(d, "fix_order", 99),
        "needs_confirmation": getattr(d, "needs_confirmation", False),
        "layer": getattr(d, "layer", ""),
    }


def report_to_dict(report):
    """Serialize a DiagnosticReport (with its CheckResults and Diagnoses) to a plain dict."""
    return {
        "schema": "network_doctor_report_v1",
        # The HTML footer carries the version, but support is often handed only this
        # JSON. Without it there is no way to know which build produced a verdict.
        "version": __version__,
        "target": getattr(report, "target", ""),
        "host": getattr(report, "host", ""),
        "port": getattr(report, "port", None),
        "overall_status": getattr(getattr(report, "overall_status", None), "value",
                                  str(getattr(report, "overall_status", ""))),
        "summary": getattr(report, "summary", ""),
        # `report_rows`, not `report.checks`: the canonical reader, so the saved artefact
        # carries every row the customer can see (gate skips included) and cannot be the
        # one surface that under-counts.
        "checks": {name: _check_to_dict(c) for name, c in (report_rows(report) or {}).items()},
        "diagnoses": [_diagnosis_to_dict(d) for d in (getattr(report, "diagnoses", []) or [])],
        # PROVENANCE ONLY — gate skips, i.e. checks the DAG never started. A check that RAN
        # and returned SKIP is in `checks` and legitimately not here. Do NOT count this array
        # to answer "how many layers were unverified": in the field that derivation gave 1
        # while the truth was 2, because `ncc_attach` ran and skipped. Read
        # `verdict_counts.unverified` / `unverified_layers` below, which are stated rather
        # than derived precisely so this mistake is not available.
        "skipped": [list(s) if isinstance(s, (list, tuple)) else s
                    for s in (getattr(report, "skipped", []) or [])],
        "verdict_counts": check_verdict_counts(report),
        "unverified_layers": unverified_layer_items(report),
    }


def report_from_dict(data):
    """Reconstruct a DiagnosticReport from report_to_dict() output.

    Relies on Status, Severity, CheckResult, Diagnosis, DiagnosticReport being in
    scope (models.py is exec-loaded into the same namespace before this module).
    """
    def _status(v):
        try:
            return Status(v)
        except Exception:
            return v

    def _severity(v):
        try:
            return Severity(v)
        except Exception:
            return v

    checks = {}
    for name, c in (data.get("checks") or {}).items():
        checks[name] = CheckResult(
            check_name=c.get("check_name", ""),
            target=c.get("target", ""),
            status=_status(c.get("status", "pass")),
            message=c.get("message", ""),
            recommendation=c.get("recommendation", ""),
            raw_output=c.get("raw_output", ""),
            duration_ms=c.get("duration_ms", 0.0),
            metadata=c.get("metadata", {}) or {},
        )

    diagnoses = []
    for d in (data.get("diagnoses") or []):
        diagnoses.append(Diagnosis(
            pattern_id=d.get("pattern_id", ""),
            title=d.get("title", ""),
            severity=_severity(d.get("severity", "info")),
            confidence=d.get("confidence", ""),
            root_cause=d.get("root_cause", ""),
            evidence=[tuple(e) if isinstance(e, list) else e for e in (d.get("evidence") or [])],
            prescription=d.get("prescription", []) or [],
            follow_up_questions=d.get("follow_up_questions", []) or [],
            fix_order=d.get("fix_order", 99),
            needs_confirmation=d.get("needs_confirmation", False),
            layer=d.get("layer", ""),
        ))

    skipped = [tuple(s) if isinstance(s, list) else s for s in (data.get("skipped") or [])]
    return DiagnosticReport(
        target=data.get("target", ""),
        host=data.get("host", ""),
        port=data.get("port"),
        # Loading is an assembly point too: a report saved by a build that predates
        # A pre-fix report has its gate skips only in `skipped`, and re-rendering it must not
        # reproduce the "0 Skipped" tile. merge_gate_skips is idempotent, so a report
        # saved WITH the rows is unchanged.
        checks=merge_gate_skips(checks, skipped),
        diagnoses=diagnoses,
        skipped=skipped,
        overall_status=_status(data.get("overall_status", "pass")),
        summary=data.get("summary", ""),
    )


def save_report_json(report, base_dir=None, path=None):
    """Persist a DiagnosticReport as JSON so it survives a serverless session reset.

    Genie Code's serverless session can drop in-memory state (the `report` variable,
    `ws_ctx`, exec-loaded functions) between turns. Saving the structured report lets
    a later follow-up turn reload it via load_saved_report() instead of re-running the
    whole diagnostic (which would re-provision a cluster and re-run probes) or stalling.

    Args:
        report: the DiagnosticReport to serialize.
        base_dir: optional destination directory (default network_doctor_reports).
        path: optional explicit .json path. If given, base_dir is ignored.

    Returns:
        Absolute JSON path written, or "" on failure (never raises).
    """
    import json
    try:
        if path is None:
            path = _report_path_stem(report, base_dir) + ".json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report_to_dict(report), f, indent=2)
        print(f"[Doctor] Structured report saved to {path}")
        return path
    except Exception as e:
        print(f"[Doctor] Could not save structured report JSON: {e}")
        return ""


def load_saved_report(path):
    """Reload a DiagnosticReport saved by save_report_json / save_dashboard_html.

    Use this in a follow-up turn after a session reset (when `report` is no longer
    defined) instead of re-running the diagnostic. Pass the .json path; the .html
    path is also accepted and the extension is swapped automatically.

    Returns the reconstructed DiagnosticReport, or raises on a genuinely missing file.
    """
    import json
    if path.endswith(".html"):
        path = path[:-len(".html")] + ".json"
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return report_from_dict(data)


def save_dashboard_html(html, report=None, base_dir=None):
    """Persist the rendered dashboard to a workspace file as a redundancy to displayHTML.

    Genie Code's inline displayHTML output is sometimes clobbered after the agent
    finishes its turn. Writing a copy to /Workspace/Users/<email>/network_doctor_reports/
    gives the customer a stable artifact they can open, share, or attach to a ticket.

    Also drops a structured JSON copy alongside the HTML (same path stem) via
    save_report_json when a report is supplied, so a follow-up turn can reload the
    report after a serverless session reset (see load_saved_report).

    Args:
        html: the HTML string returned by build_dashboard / build_dashboard_v2.
        report: optional DiagnosticReport — used to derive a stable filename prefix
            from report.target / report.host AND to write the structured JSON copy.
            Falls back to "dashboard" and no JSON when None.
        base_dir: override the destination directory. Default resolves to
            /Workspace/Users/<current_user>/network_doctor_reports.

    Returns:
        Absolute HTML file path written, or "" if the save failed (errors are
        printed but never raised — displayHTML remains the primary deliverable).
    """
    try:
        stem = _report_path_stem(report, base_dir)
        path = stem + ".html"

        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"[Doctor] Dashboard saved to {path}")

        # Drop the structured JSON next to the HTML (same stem) for cross-turn reload.
        if report is not None:
            save_report_json(report, path=stem + ".json")

        return path
    except Exception as e:
        print(f"[Doctor] Could not save dashboard to workspace file: {e}")
        return ""


def save_account_snapshot_script(script, report=None, base_dir=None):
    """Persist the read-only ACCOUNT-snapshot script beside the saved report.

    The script used to be posted INTO the chat message. Measured on
    the live run: the final message was 9,100 characters, 4,386 of them this script —
    and the customer scrolled straight past everything between `python3 - <<'PYEOF'`
    and `PYEOF`, which meant they nearly missed the two real sentences that came AFTER
    it (the Option B fallback and the report path). Their words: "It is right at the
    line, and I did not read all of it." The chat panel also mangled the wrapping
    (`"az", "account", "get-access-token", "--resource",` broke mid-argument), so it
    was not even usable as copy-paste material where it sat — untrustworthy in exactly
    the place trust matters.

    A file is the right container for a payload: it copies cleanly, it survives the
    session, and the person who has to run it is usually NOT the person reading the
    chat — it is an account admin who will be sent a path, not a transcript. The chat
    keeps a one-line pointer.

    Returns the absolute path written, or "" on failure (never raises — the prose
    hand-off in the message is the primary deliverable and must not depend on this).
    """
    if not (script or "").strip():
        return ""
    try:
        path = _report_path_stem(report, base_dir) + "_account_snapshot.py"
        with open(path, "w", encoding="utf-8") as f:
            f.write(script if script.endswith("\n") else script + "\n")
        print(f"[Doctor] Read-only account-snapshot script saved to {path}")
        return path
    except Exception as e:
        print(f"[Doctor] Could not save the account-snapshot script: {e}")
        return ""
