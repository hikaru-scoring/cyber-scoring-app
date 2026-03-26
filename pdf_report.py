# pdf_report.py
"""PDF report generation for CYBER-1000."""
from io import BytesIO
try:
    from fpdf import FPDF
    _FPDF_OK = True
except ImportError:
    _FPDF_OK = False


def _safe(text):
    """Convert text to ASCII-safe string for PDF."""
    return str(text).encode("ascii", "replace").decode("ascii")


def generate_pdf(company_data, axes_labels, logic_desc, snapshot=None):
    if not _FPDF_OK:
        return None
    try:
        return _generate_pdf_inner(company_data, axes_labels, logic_desc, snapshot)
    except Exception:
        return None


def _generate_pdf_inner(company_data, axes_labels, logic_desc, snapshot=None):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 20)
    pdf.cell(0, 12, _safe(f"CYBER-1000 Report: {company_data['name']}"), ln=True, align="C")
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 8, _safe(f"Total Cyber Risk Score: {int(company_data['total'])} / 1000"), ln=True, align="C")
    pdf.ln(6)

    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 10, "Score Breakdown", ln=True)
    pdf.set_font("Helvetica", "", 10)
    for ax in axes_labels:
        score = int(company_data["axes"].get(ax, 0))
        desc = logic_desc.get(ax, "")
        pdf.cell(0, 7, _safe(f"  {ax}: {score} / 200  --  {desc}"), ln=True)
    pdf.ln(4)

    # Insurance estimate
    premium = company_data.get("premium", {})
    if premium:
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 10, "Cyber Insurance Estimate", ln=True)
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 7, f"  Estimated Rate: {premium.get('rate_pct', 'N/A')}%", ln=True)
        pdf.cell(0, 7, f"  Coverage: ${premium.get('coverage_m', 'N/A')}M", ln=True)
        pdf.cell(0, 7, f"  Estimated Premium: ${premium.get('estimated_premium_m', 'N/A')}M/year", ln=True)
        pdf.cell(0, 7, f"  Avg Breach Cost (Industry): ${premium.get('avg_breach_cost_m', 'N/A')}M", ln=True)

    if snapshot:
        pdf.ln(4)
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 10, "Company Snapshot", ln=True)
        pdf.set_font("Helvetica", "", 10)
        for k, v in snapshot.items():
            pdf.cell(0, 7, _safe(f"  {k}: {v}"), ln=True)

    pdf.ln(6)
    pdf.set_font("Helvetica", "I", 8)
    pdf.cell(0, 5, "CYBER-1000 by SCORING PTE. LTD. For informational purposes only.", align="C")

    buf = BytesIO()
    pdf.output(buf)
    return buf.getvalue()
