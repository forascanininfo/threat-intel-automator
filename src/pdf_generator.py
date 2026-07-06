import os
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

def generate_pdf_report(lists_results, name_file="TIR.pdf"):
    doc = SimpleDocTemplate(name_file, pagesizes=letter, rightMargin=36, leftMargin=36, topMargin=36, bootomMargin=36)

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], fontSize=22, leading=26, textColor=colors.HexColor('#1A365D'), spaceAfter=12)
    text_style = styles['Normal']
    story = []
    story.append(Paragraph("THREAT INTELLIGENCE REPORT", title_style))
    story.append(Paragraph("Automated Infrastructure & IP Address Reputation Scan", styles['Italic']))
    story.append(Spacer(1,20))

    for index, data in enumerate(lists_results, 1):
        ip = data.get("ip", "N/A")
        abuse_score = data.get("abuse_score", "N/A")
        vt = data.get("virustotal", {})
        otx = data.get("alienvault", {})

        story.append(Paragraph(f"<b>{index}. Analysis Target: {ip} </b>", styles['Heading2']))
        story.append(Spacer(1,8))

        if vt:
            vt_printing = f"Malicious: {vt.get('malicious',0)} | Suspicious: {vt.get('suspicious',0)} \nHarmless: {vt.get('harmless', 0)} | Undetected: {vt.get('undetected', 0)}"
        else:
            vt_printing = "N/A"

        if otx:
            tags_str = ", ".join(otx.get("tags", [])) if otx.get("tags") else "No tags"
            if len(tags_str) > 50:
                tags_str = tags_str[:47] + "..."
            otx_printing = f"Pulses: {otx.get('number_pulses', 0)}\nTags: {tags_str}"
        else:
            otx_printing = "N/A"
            
        data_table = [
            ["Service", "Safety Indicator / Intelligence Data"],
            ["AbuseIPDB", f"Abuse Confidence Score: {abuse_score}%"],
            ["VirusTotal", vt_printing],
            ["AlienVault OTX", otx_printing]
        ]

        t = Table(data_table, colWidths=[120, 400])

        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (1, 0), colors.HexColor("#2B6CB0")),
            ('TEXTCOLOR', (0, 0), (1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0),(1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#F7FAFC')),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#E2E8F0')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))

        story.append(t)
        story.append(Spacer(1,20))
    doc.build(story)
    print(f"\n PDF report successfully generated and saved as '{name_file}' !")