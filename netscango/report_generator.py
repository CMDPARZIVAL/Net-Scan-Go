# -*- coding: utf-8 -*-
import os
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, Image
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from .config import Config

class ReportGenerator:
    """مولد تقارير PDF محسّن"""
    
    def __init__(self):
        self.reports_folder = Config.REPORTS_FOLDER
        
        # إنشاء مجلد التقارير
        if not os.path.exists(self.reports_folder):
            os.makedirs(self.reports_folder)
        
        # Styles
        self.styles = getSampleStyleSheet()
        self._create_custom_styles()
    
    def _create_custom_styles(self):
        """إنشاء أنماط مخصصة"""
        
        # Title Style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#4a9eff'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        # Heading Style
        self.styles.add(ParagraphStyle(
            name='CustomHeading',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#1f2937'),
            spaceAfter=12,
            spaceBefore=12,
            fontName='Helvetica-Bold'
        ))
        
        # Body Style
        self.styles.add(ParagraphStyle(
            name='CustomBody',
            parent=self.styles['BodyText'],
            fontSize=10,
            leading=14,
            alignment=TA_JUSTIFY,
            fontName='Helvetica'
        ))
        
        # Info Style
        self.styles.add(ParagraphStyle(
            name='InfoText',
            parent=self.styles['BodyText'],
            fontSize=9,
            textColor=colors.HexColor('#6b7280'),
            fontName='Helvetica'
        ))
    
    def generate_pdf_report(self, scan_data, vulnerabilities, ai_analysis):
        """
        إنشاء تقرير PDF كامل
        
        Args:
            scan_data: بيانات الفحص
            vulnerabilities: قائمة الثغرات
            ai_analysis: تحليل AI
        
        Returns:
            str: مسار الملف
        """
        
        # اسم الملف
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"NetScanGo_Report_{timestamp}.pdf"
        filepath = os.path.join(self.reports_folder, filename)
        
        # إنشاء المستند
        doc = SimpleDocTemplate(
            filepath,
            pagesize=A4,
            rightMargin=50,
            leftMargin=50,
            topMargin=50,
            bottomMargin=50
        )
        
        # المحتوى
        story = []
        
        # صفحة الغلاف
        story.extend(self._create_cover_page(scan_data))
        story.append(PageBreak())
        
        # الملخص التنفيذي
        story.extend(self._create_executive_summary(scan_data, vulnerabilities))
        story.append(PageBreak())
        
        # تفاصيل الثغرات
        if vulnerabilities:
            story.extend(self._create_vulnerabilities_section(vulnerabilities))
            story.append(PageBreak())
        
        # تحليل AI
        if ai_analysis and ai_analysis.get('status') == 'success':
            story.extend(self._create_ai_section(ai_analysis))
            story.append(PageBreak())
        
        # التوصيات
        story.extend(self._create_recommendations(vulnerabilities))
        
        # بناء PDF
        try:
            doc.build(story)
            print(f"✅ PDF Report created: {filepath}")
            return filepath
        except Exception as e:
            print(f"❌ PDF Error: {e}")
            raise
    
    def _create_cover_page(self, scan_data):
        """صفحة الغلاف"""
        elements = []
        
        # العنوان
        elements.append(Spacer(1, 2*inch))
        title = Paragraph("NetScanGo Pro", self.styles['CustomTitle'])
        elements.append(title)
        
        subtitle = Paragraph(
            "Network Security Vulnerability Assessment Report",
            self.styles['CustomHeading']
        )
        elements.append(subtitle)
        
        elements.append(Spacer(1, 0.5*inch))
        
        # معلومات الفحص
        info_data = [
            ['Target:', str(scan_data.get('target', 'N/A'))],
            ['Scan Date:', datetime.now().strftime('%B %d, %Y at %H:%M')],
            ['Live Hosts:', str(scan_data.get('hosts_count', 0))],
            ['Open Ports:', str(scan_data.get('ports_count', 0))],
            ['Vulnerabilities:', str(len(scan_data.get('vulnerability_summary', {}).get('by_severity', {})))]
        ]
        
        info_table = Table(info_data, colWidths=[2*inch, 4*inch])
        info_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#6b7280')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        
        elements.append(info_table)
        elements.append(Spacer(1, 1*inch))
        
        # تصنيف الخطورة
        severity = self._get_overall_severity(scan_data.get('vulnerability_summary', {}))
        severity_text = Paragraph(
            f"<font size=18><b>Security Rating: {severity['level']}</b></font>",
            self.styles['CustomBody']
        )
        elements.append(severity_text)
        
        return elements
    
    def _create_executive_summary(self, scan_data, vulnerabilities):
        """الملخص التنفيذي"""
        elements = []
        
        # العنوان
        heading = Paragraph("Executive Summary", self.styles['CustomHeading'])
        elements.append(heading)
        elements.append(Spacer(1, 0.2*inch))
        
        # الإحصائيات
        vuln_summary = scan_data.get('vulnerability_summary', {})
        stats_text = f"""
        This security assessment identified <b>{len(vulnerabilities)} vulnerabilities</b> 
        across <b>{scan_data.get('hosts_count', 0)} live hosts</b> with 
        <b>{scan_data.get('ports_count', 0)} open ports</b>.
        <br/><br/>
        <b>Severity Breakdown:</b><br/>
        - Critical: {vuln_summary.get('critical', 0)}<br/>
        - High: {vuln_summary.get('high', 0)}<br/>
        - Medium: {vuln_summary.get('medium', 0)}<br/>
        - Low: {vuln_summary.get('low', 0)}
        """
        
        stats = Paragraph(stats_text, self.styles['CustomBody'])
        elements.append(stats)
        elements.append(Spacer(1, 0.3*inch))
        
        return elements
    
    def _create_vulnerabilities_section(self, vulnerabilities):
        """قسم الثغرات"""
        elements = []
        
        # العنوان
        heading = Paragraph("Vulnerability Details", self.styles['CustomHeading'])
        elements.append(heading)
        elements.append(Spacer(1, 0.2*inch))
        
        # ترتيب حسب الخطورة
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda x: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}.get(
                x.get('severity', 'LOW'), 4
            )
        )
        
        # جدول الثغرات
        table_data = [['#', 'CVE ID', 'Severity', 'CVSS', 'Service']]
        
        for i, vuln in enumerate(sorted_vulns[:20], 1):  # أول 20
            table_data.append([
                str(i),
                str(vuln.get('cve_id', 'N/A'))[:20],
                str(vuln.get('severity', 'N/A')),
                str(vuln.get('cvss_score', 'N/A')),
                str(vuln.get('affected_service', 'N/A'))[:30]
            ])
        
        vuln_table = Table(table_data, colWidths=[0.5*inch, 1.5*inch, 1*inch, 0.8*inch, 2.2*inch])
        vuln_table.setStyle(TableStyle([
            # Header
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4a9eff')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            
            # Body
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('ALIGN', (0, 1), (0, -1), 'CENTER'),
            ('ALIGN', (2, 1), (2, -1), 'CENTER'),
            ('ALIGN', (3, 1), (3, -1), 'CENTER'),
            
            # Grid
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f9fafb')])
        ]))
        
        elements.append(vuln_table)
        elements.append(Spacer(1, 0.3*inch))
        
        return elements
    
    def _create_ai_section(self, ai_analysis):
        """قسم تحليل AI"""
        elements = []
        
        heading = Paragraph("AI Security Analysis", self.styles['CustomHeading'])
        elements.append(heading)
        elements.append(Spacer(1, 0.2*inch))
        
        analysis_text = ai_analysis.get('analysis', 'No analysis available')
        
        # تقسيم إلى فقرات
        paragraphs = analysis_text.split('\n\n')
        
        for para in paragraphs:
            if para.strip():
                # تنظيف النص
                clean_para = para.strip().replace('**', '<b>').replace('**', '</b>')
                p = Paragraph(clean_para, self.styles['CustomBody'])
                elements.append(p)
                elements.append(Spacer(1, 0.1*inch))
        
        return elements
    
    def _create_recommendations(self, vulnerabilities):
        """التوصيات"""
        elements = []
        
        heading = Paragraph("Security Recommendations", self.styles['CustomHeading'])
        elements.append(heading)
        elements.append(Spacer(1, 0.2*inch))
        
        recommendations = """
        <b>1. Immediate Actions (24 hours):</b><br/>
        - Patch all CRITICAL vulnerabilities immediately<br/>
        - Review and restrict network access to vulnerable services<br/>
        - Enable comprehensive security monitoring and logging<br/>
        <br/>
        <b>2. Short-term Actions (1 week):</b><br/>
        - Address all HIGH severity vulnerabilities<br/>
        - Implement network segmentation<br/>
        - Update firewall rules and access controls<br/>
        <br/>
        <b>3. Long-term Actions (1 month+):</b><br/>
        - Establish regular security scanning schedule<br/>
        - Implement comprehensive vulnerability management program<br/>
        - Conduct security awareness training for staff<br/>
        - Review and update security policies and procedures
        """
        
        rec_para = Paragraph(recommendations, self.styles['CustomBody'])
        elements.append(rec_para)
        
        elements.append(Spacer(1, 0.3*inch))
        
        # ملاحظة
        note = Paragraph(
            "<i>Note: This report is generated automatically. "
            "Please verify findings and consult security professionals before taking action.</i>",
            self.styles['InfoText']
        )
        elements.append(note)
        
        return elements
    
    def _get_overall_severity(self, vuln_summary):
        """تحديد مستوى الخطورة الإجمالي"""
        critical = vuln_summary.get('critical', 0)
        high = vuln_summary.get('high', 0)
        medium = vuln_summary.get('medium', 0)
        
        if critical > 0:
            return {'level': 'CRITICAL', 'color': '#dc2626'}
        elif high > 0:
            return {'level': 'HIGH RISK', 'color': '#ea580c'}
        elif medium > 0:
            return {'level': 'MEDIUM RISK', 'color': '#f59e0b'}
        else:
            return {'level': 'LOW RISK', 'color': '#10b981'}