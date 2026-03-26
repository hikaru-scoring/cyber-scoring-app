# app.py
"""CYBER-1000 — Enterprise Cyber Risk Scoring Platform."""
import io
import json
import os
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from data_logic import AXES_LABELS, LOGIC_DESC, score_all_companies, fetch_company_news
from ui_components import inject_css, render_radar_chart
try:
    from pdf_report import generate_pdf
    _PDF_AVAILABLE = True
except ImportError:
    _PDF_AVAILABLE = False

SCORES_HISTORY_FILE = os.path.join(os.path.dirname(__file__), "scores_history.json")


def _load_scores_history():
    if os.path.exists(SCORES_HISTORY_FILE):
        with open(SCORES_HISTORY_FILE, "r") as f:
            return json.load(f)
    return {}


def render_score_delta(name, current_total):
    history = _load_scores_history()
    if not history:
        return
    dates = sorted(history.keys(), reverse=True)
    prev = None
    for d in dates:
        s = history[d].get(name)
        if s is not None:
            prev = s
            break
    if prev is None:
        return
    delta = current_total - prev
    if delta > 0:
        color, arrow = "#10b981", "&#9650;"
    elif delta < 0:
        color, arrow = "#ef4444", "&#9660;"
    else:
        color, arrow = "#94a3b8", "&#9644;"
    st.markdown(
        f'<div style="text-align:center;font-size:1.1em;font-weight:700;color:{color};margin-top:-8px;margin-bottom:10px;">'
        f'{arrow} {delta:+d} from last record ({prev})</div>',
        unsafe_allow_html=True,
    )


def generate_excel(data, axes_labels, logic_desc):
    rows = []
    for k in axes_labels:
        desc = logic_desc.get(k, "")
        rows.append({"Axis": k, "Score": int(data["axes"].get(k, 0)), "Max": 200, "Description": desc})
    rows.append({"Axis": "TOTAL", "Score": int(data.get("total", 0)), "Max": 1000, "Description": ""})
    premium = data.get("premium", {})
    if premium:
        rows.append({"Axis": "", "Score": "", "Max": "", "Description": ""})
        rows.append({"Axis": "Insurance Rate", "Score": f"{premium.get('rate_pct', '')}%", "Max": "", "Description": ""})
        rows.append({"Axis": "Coverage", "Score": f"${premium.get('coverage_m', '')}M", "Max": "", "Description": ""})
        rows.append({"Axis": "Est. Premium", "Score": f"${premium.get('estimated_premium_m', '')}M/yr", "Max": "", "Description": ""})
    return pd.DataFrame(rows).to_csv(index=False).encode("utf-8")


# ── Page config ──
APP_TITLE = "CYBER-1000 — Enterprise Cyber Risk Scoring"
st.set_page_config(page_title=APP_TITLE, layout="wide")
inject_css()
st.markdown("""
<style>
.block-container { padding-top: 1rem !important; }
header[data-testid="stHeader"] { display: none !important; }
footer { display: none !important; }
#MainMenu { display: none !important; }
.stDeployButton { display: none !important; }
div[class*="stToolbar"] { display: none !important; }
div[data-testid="stStatusWidget"] { display: none !important; }
</style>
""", unsafe_allow_html=True)

# ── Load data ──
@st.cache_data(ttl=3600)
def load_data():
    return score_all_companies()

all_companies = load_data()
company_map = {c["name"]: c for c in all_companies}

# ── Tabs ──
tab_dash, tab_detail, tab_rank, tab_insurance = st.tabs(["Dashboard", "Company Detail", "Rankings", "Insurance Estimator"])

# ═══════════════════════════════════════════════════════════════
# TAB 1 — Dashboard
# ═══════════════════════════════════════════════════════════════
with tab_dash:
    st.markdown("""
    <h2 style='color:#1a3c6e; margin-bottom:2px;'>CYBER-1000</h2>
    <p style='color:#555; font-size:1.05em; margin-bottom:2px;'>
    Every enterprise scored on the same 0–1,000 scale across 5 cyber risk dimensions.
    A higher score means the company has a stronger cybersecurity posture.
    Scores are derived from public data only — no access to internal systems.</p>
    """, unsafe_allow_html=True)
    st.caption(f"{len(all_companies)} companies scored | Data: Shodan, NVD, CISA, HIBP")

    # Market Health
    avg_score = int(sum(int(c["total"]) for c in all_companies) / len(all_companies))
    if avg_score >= 700:
        health_label, health_color, health_bg = "Strong", "#10b981", "#f0fdf4"
    elif avg_score >= 500:
        health_label, health_color, health_bg = "Moderate", "#f59e0b", "#fffbeb"
    else:
        health_label, health_color, health_bg = "Weak", "#ef4444", "#fef2f2"

    mh1, mh2, mh3 = st.columns(3)
    mh1.markdown(f"""
    <div style="background:{health_bg}; padding:24px; border-radius:16px; text-align:center; border:2px solid {health_color};">
        <div style="font-size:0.75em; font-weight:700; color:#64748b; letter-spacing:1px;">MARKET AVG SCORE</div>
        <div style="font-size:2.8em; font-weight:900; color:{health_color}; line-height:1.1;">{avg_score}</div>
        <div style="font-size:0.9em; font-weight:700; color:{health_color};">{health_label}</div>
    </div>
    """, unsafe_allow_html=True)
    top5_avg = int(sum(int(c["total"]) for c in all_companies[:5]) / 5)
    bot5_avg = int(sum(int(c["total"]) for c in all_companies[-5:]) / 5)
    mh2.markdown(f"""
    <div style="background:#fff; padding:24px; border-radius:16px; text-align:center; border:1px solid #e2e8f0;">
        <div style="font-size:0.75em; font-weight:700; color:#10b981; letter-spacing:1px;">TOP 5 AVG</div>
        <div style="font-size:2.8em; font-weight:900; color:#1e293b; line-height:1.1;">{top5_avg}</div>
    </div>
    """, unsafe_allow_html=True)
    mh3.markdown(f"""
    <div style="background:#fff; padding:24px; border-radius:16px; text-align:center; border:1px solid #e2e8f0;">
        <div style="font-size:0.75em; font-weight:700; color:#ef4444; letter-spacing:1px;">BOTTOM 5 AVG</div>
        <div style="font-size:2.8em; font-weight:900; color:#1e293b; line-height:1.1;">{bot5_avg}</div>
    </div>
    """, unsafe_allow_html=True)

    # Sector filter
    sectors = sorted(set(c.get("sector", "") for c in all_companies))
    selected_sector = st.selectbox("Filter by Sector", ["All Sectors"] + sectors, key="sector_filter")
    filtered = all_companies if selected_sector == "All Sectors" else [c for c in all_companies if c.get("sector") == selected_sector]

    # All companies grid
    st.markdown("<div style='font-size:1.1em; font-weight:700; color:#1a3c6e; margin:15px 0 10px; border-left:4px solid #1a3c6e; padding-left:10px;'>All Companies</div>", unsafe_allow_html=True)
    cols = st.columns(5)
    for idx, c in enumerate(filtered):
        score = int(c["total"])
        if score >= 800:
            sc_color = "#10b981"
        elif score >= 600:
            sc_color = "#2E7BE6"
        elif score >= 400:
            sc_color = "#f59e0b"
        else:
            sc_color = "#ef4444"

        cols[idx % 5].markdown(f"""
        <div style="background:#fff; padding:18px; border-radius:14px; border:1px solid #e2e8f0; text-align:center; margin-bottom:10px; box-shadow:0 2px 8px rgba(0,0,0,0.04);">
            <div style="font-size:0.8em; font-weight:600; color:#64748b; margin-bottom:6px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">{c['name']}</div>
            <div style="font-size:2em; font-weight:900; color:{sc_color}; line-height:1;">{score}</div>
            <div style="font-size:0.7em; color:#ccc;">/ 1000</div>
            <div style="font-size:0.7em; color:#94a3b8; margin-top:4px;">{c.get('sector', '')}</div>
        </div>
        """, unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════
# TAB 2 — Company Detail
# ═══════════════════════════════════════════════════════════════
with tab_detail:
    company_names = [c["name"] for c in all_companies]
    sel_name = st.selectbox("Select Company", company_names, key="sel_company")
    selected = company_map[sel_name]
    total = int(selected["total"])
    company = selected["company"]
    premium = selected.get("premium", {})

    # Compare
    compare_names = ["(none)"] + [n for n in company_names if n != sel_name]
    comp_name = st.selectbox("Compare with", compare_names, key="comp_company")
    compare_data = company_map.get(comp_name) if comp_name != "(none)" else None

    # Buttons
    bc1, bc2, bc3, bc4 = st.columns(4)
    with bc1:
        save_it = st.button("Save", key="btn_save")
    with bc2:
        clear_it = st.button("Clear", key="btn_clear")
    with bc3:
        if _PDF_AVAILABLE:
            snapshot = {"Domain": company["domain"], "Sector": company["sector"],
                        "Revenue": f"${company['revenue_b']}B", "Employees": f"{company['employees']:,}"}
            pdf_bytes = generate_pdf(selected, AXES_LABELS, LOGIC_DESC, snapshot)
            if pdf_bytes:
                st.download_button("PDF", pdf_bytes, f"CYBER_1000_{sel_name}.pdf", "application/pdf", key="btn_pdf")
    with bc4:
        excel_data = generate_excel(selected, AXES_LABELS, LOGIC_DESC)
        st.download_button("Excel", excel_data, f"CYBER_1000_{sel_name}.csv", "text/csv", key="btn_excel")

    if save_it:
        st.session_state.saved_company = selected
        st.rerun()
    if clear_it:
        st.session_state.saved_company = None
        st.rerun()

    # Total Score
    st.markdown(f"""
    <div style="text-align:center;margin:10px 0;">
        <div style="font-size:14px;letter-spacing:2px;color:#666;">TOTAL SCORE</div>
        <div style="font-size:80px;font-weight:800;color:#2E7BE6;line-height:1;">
            {total}<span style="font-size:30px;color:#BBB;"> / 1000</span>
        </div>
    </div>""", unsafe_allow_html=True)

    render_score_delta(sel_name, total)

    # Radar + Score Metrics
    col_r, col_a = st.columns([1.5, 1])
    with col_r:
        st.markdown("<div style='font-size:1.1em;font-weight:bold;color:#333;margin-top:-10px;margin-bottom:5px;'>I. Intelligence Radar</div>", unsafe_allow_html=True)
        fig_r = render_radar_chart(selected, compare_data, AXES_LABELS)
        st.plotly_chart(fig_r, use_container_width=True, config={"displayModeBar": False}, key="radar_detail")
    with col_a:
        st.markdown("<div style='font-size:0.9em;font-weight:bold;color:#333;margin-top:-10px;margin-bottom:15px;border-left:3px solid #2E7BE6;padding-left:8px;'>II. ANALYSIS SCORE METRICS</div>", unsafe_allow_html=True)
        saved = st.session_state.get("saved_company")
        for ax in AXES_LABELS:
            v1 = int(selected["axes"].get(ax, 0))
            v2 = int(saved["axes"].get(ax, 0)) if saved else None
            desc_text = LOGIC_DESC.get(ax, "")
            score_html = f'<span style="color: #2E7BE6;">{v1}</span><span style="color:#bbb;font-size:0.5em;font-weight:600;"> /200</span>'
            if v2 is not None:
                score_html += f' <span style="color: #ccc; font-size: 0.9em; font-weight:bold; margin: 0 6px;">vs</span> <span style="color: #F4A261;">{v2}</span><span style="color:#bbb;font-size:0.5em;font-weight:600;"> /200</span>'
            st.markdown(f"""
            <div style="background-color: #FFFFFF; padding: 20px; border-radius: 12px; margin-bottom: 12px;
                border: 1px solid #E0E0E0; border-left: 8px solid #2E7BE6; box-shadow: 2px 2px 5px rgba(0,0,0,0.07);">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                    <span style="font-size: 1.4em; font-weight: 800; color: #333333;">{ax}</span>
                    <span style="font-size: 1.9em; font-weight: 900; line-height: 1;">{score_html}</span>
                </div>
                <p style="font-size: 1.05em; color: #777777; margin: 0; line-height: 1.3; font-weight: 500;">{desc_text}</p>
            </div>""", unsafe_allow_html=True)

    # Company Snapshot
    st.markdown("<div class='section-title'>III. Company Snapshot</div>", unsafe_allow_html=True)
    s1, s2 = st.columns(2)
    with s1:
        shodan = selected.get("shodan", {})
        st.markdown(f"""
        <div class='card'>
            <div style='font-size:11px;color:#999;'>DOMAIN</div>
            <div style='font-size:16px;font-weight:700;'>{company['domain']}</div>
            <div style='font-size:11px;color:#999;margin-top:8px;'>SECTOR</div>
            <div style='font-size:16px;font-weight:700;'>{company['sector']}</div>
            <div style='font-size:11px;color:#999;margin-top:8px;'>REVENUE</div>
            <div style='font-size:16px;font-weight:700;'>${company['revenue_b']}B</div>
            <div style='font-size:11px;color:#999;margin-top:8px;'>EMPLOYEES</div>
            <div style='font-size:16px;font-weight:700;'>{company['employees']:,}</div>
        </div>""", unsafe_allow_html=True)
    with s2:
        ports = shodan.get("ports", [])
        vulns = shodan.get("vulns", [])
        breaches = selected.get("breaches", [])
        st.markdown(f"""
        <div class='card'>
            <div style='font-size:11px;color:#999;'>OPEN PORTS</div>
            <div style='font-size:16px;font-weight:700;'>{', '.join(str(p) for p in ports) if ports else 'None detected'}</div>
            <div style='font-size:11px;color:#999;margin-top:8px;'>KNOWN VULNERABILITIES</div>
            <div style='font-size:16px;font-weight:700;color:{"#ef4444" if vulns else "#10b981"};'>{len(vulns)} CVEs</div>
            <div style='font-size:11px;color:#999;margin-top:8px;'>DATA BREACHES</div>
            <div style='font-size:16px;font-weight:700;color:{"#ef4444" if breaches else "#10b981"};'>{len(breaches)} known breaches</div>
            <div style='font-size:11px;color:#999;margin-top:8px;'>IP ADDRESS</div>
            <div style='font-size:16px;font-weight:700;'>{shodan.get('ip', 'N/A')}</div>
        </div>""", unsafe_allow_html=True)

    # Insurance Estimate
    if premium:
        st.markdown("<div class='section-title'>IV. Cyber Insurance Estimate</div>", unsafe_allow_html=True)
        ic1, ic2, ic3, ic4 = st.columns(4)
        ic1.markdown(f"""
        <div class='card' style='text-align:center;'>
            <div style='font-size:11px;color:#999;'>ESTIMATED RATE</div>
            <div style='font-size:24px;font-weight:900;color:#2E7BE6;'>{premium['rate_pct']}%</div>
        </div>""", unsafe_allow_html=True)
        ic2.markdown(f"""
        <div class='card' style='text-align:center;'>
            <div style='font-size:11px;color:#999;'>COVERAGE</div>
            <div style='font-size:24px;font-weight:900;color:#333;'>${premium['coverage_m']}M</div>
        </div>""", unsafe_allow_html=True)
        ic3.markdown(f"""
        <div class='card' style='text-align:center;'>
            <div style='font-size:11px;color:#999;'>EST. PREMIUM</div>
            <div style='font-size:24px;font-weight:900;color:#f59e0b;'>${premium['estimated_premium_m']}M/yr</div>
        </div>""", unsafe_allow_html=True)
        ic4.markdown(f"""
        <div class='card' style='text-align:center;'>
            <div style='font-size:11px;color:#999;'>AVG BREACH COST</div>
            <div style='font-size:24px;font-weight:900;color:#ef4444;'>${premium.get('avg_breach_cost_m', 'N/A')}M</div>
        </div>""", unsafe_allow_html=True)

    # Breach History
    if breaches:
        st.markdown("<div class='section-title'>V. Breach History</div>", unsafe_allow_html=True)
        for b in breaches:
            pwn = b.get("pwn_count", 0)
            st.markdown(f"""
            <div style="padding:10px 0; border-bottom:1px solid #F0F0F0;">
                <div style="font-weight:700; color:#1e3a8a;">{b['name']}</div>
                <div style="font-size:0.85em; color:#666;">Date: {b.get('date', 'Unknown')} | Records: {pwn:,} | Data: {', '.join(b.get('data_classes', [])[:3])}</div>
            </div>""", unsafe_allow_html=True)

    # News
    st.markdown("<div class='section-title'>VI. Latest Cyber News</div>", unsafe_allow_html=True)
    news = fetch_company_news(sel_name)
    if news:
        for n in news[:5]:
            st.markdown(
                f'<div style="padding:10px 0; border-bottom:1px solid #F0F0F0;">'
                f'<a href="{n["link"]}" target="_blank" style="font-size:0.95em; font-weight:600; color:#1e3a8a; text-decoration:none;">{n["title"]}</a>'
                f'<div style="font-size:0.8em; color:#999; margin-top:3px;">{n["source"]} · {n["date"][:16] if n["date"] else ""}</div>'
                f'</div>',
                unsafe_allow_html=True,
            )
    else:
        st.caption("No recent news found.")

# ═══════════════════════════════════════════════════════════════
# TAB 3 — Rankings
# ═══════════════════════════════════════════════════════════════
with tab_rank:
    st.markdown("<div class='section-title'>CYBER-1000 Rankings</div>", unsafe_allow_html=True)

    sort_by = st.selectbox("Sort by", ["Total Score"] + AXES_LABELS, key="rank_sort")
    if sort_by == "Total Score":
        sorted_companies = sorted(all_companies, key=lambda x: x["total"], reverse=True)
    else:
        sorted_companies = sorted(all_companies, key=lambda x: x["axes"].get(sort_by, 0), reverse=True)

    rows = []
    for i, c in enumerate(sorted_companies):
        row = {"Rank": i + 1, "Company": c["name"], "Sector": c.get("sector", ""), "Total Score": int(c["total"])}
        for ax in AXES_LABELS:
            row[ax] = int(c["axes"].get(ax, 0))
        p = c.get("premium", {})
        row["Insurance Rate"] = f"{p.get('rate_pct', '')}%"
        rows.append(row)

    df = pd.DataFrame(rows)
    st.dataframe(df, use_container_width=True, hide_index=True, height=750)

    csv_buf = io.StringIO()
    df.to_csv(csv_buf, index=False)
    st.download_button("Download Excel (All Companies)", csv_buf.getvalue().encode(), "cyber_1000_rankings.csv", "text/csv", key="btn_csv_rank")

    # Score Distribution
    st.markdown("<div class='section-title'>Score Distribution</div>", unsafe_allow_html=True)
    fig_dist = px.histogram(df, x="Total Score", nbins=10, color_discrete_sequence=["#2E7BE6"])
    fig_dist.update_layout(height=300, margin=dict(l=0, r=0, t=10, b=0), plot_bgcolor="white")
    st.plotly_chart(fig_dist, use_container_width=True, config={"displayModeBar": False}, key="dist_rank")

    # Sector Average
    st.markdown("<div class='section-title'>Score by Sector</div>", unsafe_allow_html=True)
    sector_scores = {}
    for c in all_companies:
        s = c.get("sector", "Other")
        sector_scores.setdefault(s, []).append(int(c["total"]))
    sector_avg = {s: int(sum(v)/len(v)) for s, v in sector_scores.items()}
    sector_df = pd.DataFrame(sorted(sector_avg.items(), key=lambda x: x[1], reverse=True), columns=["Sector", "Avg Score"])
    fig_sector = px.bar(sector_df, x="Sector", y="Avg Score", color_discrete_sequence=["#2E7BE6"])
    fig_sector.update_layout(height=350, margin=dict(l=0, r=0, t=10, b=0), plot_bgcolor="white")
    st.plotly_chart(fig_sector, use_container_width=True, config={"displayModeBar": False}, key="sector_rank")

# ═══════════════════════════════════════════════════════════════
# TAB 4 — Insurance Estimator
# ═══════════════════════════════════════════════════════════════
with tab_insurance:
    st.markdown("<div class='section-title'>Cyber Insurance Premium Estimator</div>", unsafe_allow_html=True)
    st.markdown("""
    <p style='color:#555;'>Estimated cyber insurance premiums based on CYBER-1000 scores.
    Higher scores lead to lower premiums. This is an estimate, not actual market pricing.</p>
    """, unsafe_allow_html=True)

    ins_rows = []
    for c in sorted(all_companies, key=lambda x: x.get("premium", {}).get("rate_pct", 99)):
        p = c.get("premium", {})
        ins_rows.append({
            "Company": c["name"],
            "Score": int(c["total"]),
            "Sector": c.get("sector", ""),
            "Rate (%)": p.get("rate_pct", ""),
            "Coverage ($M)": p.get("coverage_m", ""),
            "Est. Premium ($M/yr)": p.get("estimated_premium_m", ""),
            "Avg Breach Cost ($M)": p.get("avg_breach_cost_m", ""),
        })

    ins_df = pd.DataFrame(ins_rows)
    st.dataframe(ins_df, use_container_width=True, hide_index=True, height=600)

    csv_ins = io.StringIO()
    ins_df.to_csv(csv_ins, index=False)
    st.download_button("Download Insurance Report", csv_ins.getvalue().encode(), "cyber_1000_insurance.csv", "text/csv", key="btn_csv_ins")

# Footer
st.markdown("---")
st.markdown(
    "<div style='text-align:center;color:#aaa;font-size:12px;'>"
    "CYBER-1000 by SCORING PTE. LTD. For informational purposes only. "
    "Scores are derived from publicly available data. Not affiliated with any company scored.</div>",
    unsafe_allow_html=True,
)
