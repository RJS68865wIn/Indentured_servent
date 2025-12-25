"""
Report Generator for Indentured Servant
Generates professional PDF, HTML, and JSON reports from scan results
"""
import json
import os
import base64
import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, asdict
import webbrowser

from src.utils.logger import setup_logger, log_function_call
from src.secure_config import WindowsSecureConfig

try:
    from fpdf import FPDF
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False
    print("Warning: fpdf not installed. PDF reports will be limited.")

try:
    import matplotlib.pyplot as plt
    import matplotlib
    matplotlib.use('Agg')  # Use non-interactive backend
    CHARTS_AVAILABLE = True
except ImportError:
    CHARTS_AVAILABLE = False
    print("Warning: matplotlib not installed. Charts will be limited.")

@dataclass
class ReportConfig:
    """Report generation configuration"""
    format: str  # pdf, html, json, txt
    title: str
    include_charts: bool
    include_details: bool
    include_recommendations: bool
    include_threats: bool
    include_system_info: bool
    include_executive_summary: bool
    watermark: bool
    password_protect: bool
    company_logo: Optional[str] = None
    company_name: str = "Indentured Servant"
    company_url: str = "https://indenturedservant.com"

@dataclass
class ReportData:
    """Data container for report generation"""
    scan_results: Dict[str, Any]
    network_scan: Optional[List[Dict[str, Any]]] = None
    system_info: Optional[Dict[str, Any]] = None
    ai_analysis: Optional[str] = None
    custom_sections: Optional[List[Dict[str, Any]]] = None

class ReportGenerator:
    """
    Professional report generator for cybersecurity findings
    Supports PDF, HTML, JSON, and plain text formats
    """
    
    def __init__(self):
        self.logger = setup_logger("ReportGenerator")
        self.config = WindowsSecureConfig()
        
        # Template directory
        self.template_dir = Path("data/report_templates")
        self.template_dir.mkdir(parents=True, exist_ok=True)
        
        # Output directory
        self.output_dir = Path("data/reports")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Load report templates
        self._load_templates()
    
    @log_function_call
    def generate_report(self, 
                       report_data: ReportData,
                       report_config: ReportConfig) -> Dict[str, Any]:
        """
        Generate a security report
        
        Args:
            report_data: Data to include in report
            report_config: Report configuration
            
        Returns:
            Dictionary with report generation results
        """
        try:
            # Generate report based on format
            if report_config.format.lower() == 'pdf':
                result = self._generate_pdf_report(report_data, report_config)
            elif report_config.format.lower() == 'html':
                result = self._generate_html_report(report_data, report_config)
            elif report_config.format.lower() == 'json':
                result = self._generate_json_report(report_data, report_config)
            elif report_config.format.lower() == 'txt':
                result = self._generate_text_report(report_data, report_config)
            else:
                raise ValueError(f"Unsupported format: {report_config.format}")
            
            self.logger.info(f"Report generated: {result['file_path']}")
            return result
            
        except Exception as e:
            self.logger.error(f"Report generation failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'file_path': None
            }
    
    @log_function_call
    def generate_comprehensive_report(self, 
                                     scan_id: str,
                                     report_config: Optional[ReportConfig] = None) -> Dict[str, Any]:
        """
        Generate comprehensive report from scan ID
        
        Args:
            scan_id: Scan identifier
            report_config: Optional report configuration
            
        Returns:
            Dictionary with report generation results
        """
        try:
            # Load scan results
            scan_file = self.output_dir / f"{scan_id}.json"
            if not scan_file.exists():
                return {
                    'success': False,
                    'error': f"Scan file not found: {scan_file}",
                    'file_path': None
                }
            
            with open(scan_file, 'r') as f:
                scan_results = json.load(f)
            
            # Get system info
            from .utils.windows_tools import get_system_info
            system_info = get_system_info()
            
            # Get AI analysis if available
            ai_analysis = self._generate_ai_analysis(scan_results)
            
            # Create report data
            report_data = ReportData(
                scan_results=scan_results,
                system_info=system_info,
                ai_analysis=ai_analysis
            )
            
            # Use default config if not provided
            if report_config is None:
                report_config = ReportConfig(
                    format="pdf",
                    title=f"Security Report - Scan {scan_id}",
                    include_charts=True,
                    include_details=True,
                    include_recommendations=True,
                    include_threats=True,
                    include_system_info=True,
                    include_executive_summary=True,
                    watermark=True,
                    password_protect=False
                )
            
            # Generate report
            return self.generate_report(report_data, report_config)
            
        except Exception as e:
            self.logger.error(f"Comprehensive report failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'file_path': None
            }
    
    @log_function_call
    def generate_weekly_report(self, 
                              start_date: datetime.datetime,
                              end_date: datetime.datetime,
                              report_config: Optional[ReportConfig] = None) -> Dict[str, Any]:
        """
        Generate weekly security report
        
        Args:
            start_date: Start date for report period
            end_date: End date for report period
            report_config: Optional report configuration
            
        Returns:
            Dictionary with report generation results
        """
        try:
            # Load all scans in date range
            scans = self._get_scans_in_range(start_date, end_date)
            
            if not scans:
                return {
                    'success': False,
                    'error': "No scans found in date range",
                    'file_path': None
                }
            
            # Aggregate data
            aggregated = self._aggregate_weekly_data(scans)
            
            # Create report data
            report_data = ReportData(
                scan_results=aggregated,
                system_info=self._get_weekly_system_info(),
                custom_sections=[
                    {
                        'title': 'Weekly Summary',
                        'content': self._generate_weekly_summary(aggregated)
                    },
                    {
                        'title': 'Trend Analysis',
                        'content': self._generate_trend_analysis(scans)
                    }
                ]
            )
            
            # Use default config if not provided
            if report_config is None:
                report_config = ReportConfig(
                    format="pdf",
                    title=f"Weekly Security Report - {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}",
                    include_charts=True,
                    include_details=True,
                    include_recommendations=True,
                    include_threats=True,
                    include_system_info=True,
                    include_executive_summary=True,
                    watermark=True,
                    password_protect=False
                )
            
            # Generate report
            return self.generate_report(report_data, report_config)
            
        except Exception as e:
            self.logger.error(f"Weekly report failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'file_path': None
            }
    
    # ===== PRIVATE METHODS =====
    
    def _load_templates(self):
        """Load report templates"""
        self.templates = {
            'html': self._load_html_template(),
            'pdf_style': self._load_pdf_style(),
            'executive_summary': self._load_executive_summary_template()
        }
    
    def _load_html_template(self) -> str:
        """Load HTML report template"""
        template_file = self.template_dir / "report_template.html"
        
        if template_file.exists():
            with open(template_file, 'r', encoding='utf-8') as f:
                return f.read()
        
        # Default HTML template
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{title}} - Indentured Servant</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Arial, sans-serif; 
            line-height: 1.6; 
            color: #333; 
            background: #f5f5f5;
            padding: 20px;
        }
        .report-container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #1e3c72, #2a5298);
            color: white;
            padding: 40px;
            text-align: center;
            position: relative;
        }
        .header h1 { 
            font-size: 2.5em; 
            margin-bottom: 10px;
            font-weight: 300;
        }
        .header .subtitle {
            font-size: 1.2em;
            opacity: 0.9;
            margin-bottom: 20px;
        }
        .header .logo {
            position: absolute;
            top: 20px;
            left: 40px;
            font-size: 1.5em;
            font-weight: bold;
        }
        .report-meta {
            background: #f8f9fa;
            padding: 20px 40px;
            border-bottom: 1px solid #dee2e6;
            display: flex;
            justify-content: space-between;
            flex-wrap: wrap;
        }
        .meta-item {
            margin: 5px 0;
        }
        .content {
            padding: 40px;
        }
        .section {
            margin-bottom: 40px;
        }
        .section-title {
            font-size: 1.8em;
            color: #2a5298;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #e9ecef;
        }
        .subsection {
            margin-bottom: 25px;
        }
        .subsection-title {
            font-size: 1.3em;
            color: #495057;
            margin-bottom: 10px;
        }
        .threat-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        .threat-card {
            background: #f8f9fa;
            border-left: 4px solid #dc3545;
            padding: 15px;
            border-radius: 5px;
        }
        .threat-card.low { border-left-color: #28a745; }
        .threat-card.medium { border-left-color: #ffc107; }
        .threat-card.high { border-left-color: #fd7e14; }
        .threat-card.critical { border-left-color: #dc3545; }
        .threat-title {
            font-weight: bold;
            margin-bottom: 5px;
        }
        .threat-severity {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 0.8em;
            font-weight: bold;
            margin-bottom: 10px;
        }
        .severity-critical { background: #dc3545; color: white; }
        .severity-high { background: #fd7e14; color: white; }
        .severity-medium { background: #ffc107; color: white; }
        .severity-low { background: #28a745; color: white; }
        .chart-container {
            margin: 20px 0;
            text-align: center;
        }
        .chart-container img {
            max-width: 100%;
            height: auto;
            border: 1px solid #dee2e6;
            border-radius: 5px;
        }
        .recommendation-list {
            list-style: none;
        }
        .recommendation-list li {
            background: #e8f4fd;
            margin: 10px 0;
            padding: 15px;
            border-left: 4px solid #2a5298;
            border-radius: 5px;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .stat-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .stat-value {
            font-size: 2.5em;
            font-weight: bold;
            color: #2a5298;
            margin: 10px 0;
        }
        .stat-label {
            color: #6c757d;
            font-size: 0.9em;
        }
        .footer {
            background: #343a40;
            color: white;
            padding: 30px 40px;
            text-align: center;
            margin-top: 40px;
        }
        .footer p {
            margin: 5px 0;
            opacity: 0.8;
        }
        .watermark {
            position: fixed;
            bottom: 20px;
            right: 20px;
            opacity: 0.1;
            font-size: 8em;
            color: #2a5298;
            pointer-events: none;
            z-index: -1;
            transform: rotate(-45deg);
        }
        @media print {
            body { background: white; }
            .report-container { box-shadow: none; }
            .footer { page-break-inside: avoid; }
        }
    </style>
</head>
<body>
    <div class="watermark">INDENTURED SERVANT</div>
    
    <div class="report-container">
        <div class="header">
            <div class="logo">🔒 IS</div>
            <h1>{{title}}</h1>
            <div class="subtitle">Comprehensive Security Analysis Report</div>
        </div>
        
        <div class="report-meta">
            <div class="meta-item"><strong>Generated:</strong> {{generated_date}}</div>
            <div class="meta-item"><strong>Report ID:</strong> {{report_id}}</div>
            <div class="meta-item"><strong>System:</strong> {{system_name}}</div>
            <div class="meta-item"><strong>Security Score:</strong> {{security_score}}/100</div>
        </div>
        
        <div class="content">
            <!-- Content will be inserted here -->
            {{content}}
        </div>
        
        <div class="footer">
            <p><strong>Indentured Servant - Cybersecurity Assistant</strong></p>
            <p>Generated automatically. For security purposes only.</p>
            <p>© {{current_year}} {{company_name}} | {{company_url}}</p>
            <p>Confidential - Do not distribute without authorization</p>
        </div>
    </div>
</body>
</html>"""
    
    def _load_pdf_style(self) -> Dict[str, Any]:
        """Load PDF styling configuration"""
        return {
            'primary_color': (42, 82, 152),  # #2a5298
            'secondary_color': (220, 53, 69),  # #dc3545
            'success_color': (40, 167, 69),  # #28a745
            'warning_color': (255, 193, 7),  # #ffc107
            'font_family': 'Arial',
            'header_font_size': 16,
            'title_font_size': 24,
            'normal_font_size': 11,
            'small_font_size': 9
        }
    
    def _load_executive_summary_template(self) -> str:
        """Load executive summary template"""
        return """EXECUTIVE SUMMARY

Report Period: {{report_period}}
Generated: {{generated_date}}

OVERVIEW
This security report provides a comprehensive analysis of the system's security posture
based on scans conducted during the reporting period. The report includes threat
detections, vulnerability assessments, and actionable recommendations.

KEY FINDINGS
• Overall Security Score: {{security_score}}/100
• Threats Detected: {{threats_count}}
• Critical Issues: {{critical_count}}
• High Severity Issues: {{high_count}}
• System Vulnerabilities: {{vulnerabilities_count}}

RISK ASSESSMENT
{{risk_assessment}}

IMMEDIATE ACTIONS REQUIRED
{{immediate_actions}}

RECOMMENDATIONS SUMMARY
{{recommendations_summary}}

CONCLUSION
{{conclusion}}"""
    
    def _generate_pdf_report(self, report_data: ReportData, report_config: ReportConfig) -> Dict[str, Any]:
        """Generate PDF report"""
        if not PDF_AVAILABLE:
            raise ImportError("fpdf module not installed. Install with: pip install fpdf")
        
        try:
            # Create PDF
            pdf = FPDF()
            pdf.set_auto_page_break(auto=True, margin=15)
            style = self.templates['pdf_style']
            
            # Add first page
            pdf.add_page()
            
            # Add header
            self._add_pdf_header(pdf, report_config, style)
            
            # Add metadata
            self._add_pdf_metadata(pdf, report_data, report_config, style)
            
            # Add table of contents if detailed report
            if report_config.include_details:
                self._add_pdf_toc(pdf, report_data, style)
            
            # Add executive summary
            if report_config.include_executive_summary:
                self._add_pdf_executive_summary(pdf, report_data, report_config, style)
                pdf.add_page()
            
            # Add system information
            if report_config.include_system_info and report_data.system_info:
                self._add_pdf_system_info(pdf, report_data.system_info, style)
                pdf.ln(10)
            
            # Add scan results
            if report_config.include_details:
                self._add_pdf_scan_results(pdf, report_data.scan_results, style)
                pdf.add_page()
            
            # Add threats
            if report_config.include_threats and report_data.scan_results.get('threats'):
                self._add_pdf_threats(pdf, report_data.scan_results['threats'], style)
                pdf.ln(10)
            
            # Add charts
            if report_config.include_charts and CHARTS_AVAILABLE:
                self._add_pdf_charts(pdf, report_data, style)
                pdf.add_page()
            
            # Add recommendations
            if report_config.include_recommendations and report_data.scan_results.get('recommendations'):
                self._add_pdf_recommendations(pdf, report_data.scan_results['recommendations'], style)
            
            # Add custom sections
            if report_data.custom_sections:
                for section in report_data.custom_sections:
                    self._add_pdf_custom_section(pdf, section, style)
                    pdf.ln(10)
            
            # Add footer
            self._add_pdf_footer(pdf, report_config, style)
            
            # Generate filename
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"security_report_{timestamp}.pdf"
            filepath = self.output_dir / filename
            
            # Save PDF
            pdf.output(str(filepath))
            
            # Add watermark if requested
            if report_config.watermark:
                self._add_watermark_to_pdf(str(filepath), report_config.company_name)
            
            # Password protect if requested
            if report_config.password_protect:
                self._password_protect_pdf(str(filepath))
            
            return {
                'success': True,
                'file_path': str(filepath),
                'format': 'pdf',
                'size': os.path.getsize(filepath),
                'pages': pdf.page_no()
            }
            
        except Exception as e:
            self.logger.error(f"PDF generation failed: {e}")
            raise
    
    def _add_pdf_header(self, pdf: FPDF, report_config: ReportConfig, style: Dict[str, Any]):
        """Add PDF header"""
        # Title
        pdf.set_font(style['font_family'], 'B', style['title_font_size'])
        pdf.set_text_color(*style['primary_color'])
        pdf.cell(0, 10, report_config.title, ln=True, align='C')
        pdf.ln(5)
        
        # Subtitle
        pdf.set_font(style['font_family'], 'I', style['normal_font_size'])
        pdf.set_text_color(100, 100, 100)
        pdf.cell(0, 10, "Comprehensive Security Analysis Report", ln=True, align='C')
        pdf.ln(10)
        
        # Logo if available
        if report_config.company_logo and os.path.exists(report_config.company_logo):
            try:
                pdf.image(report_config.company_logo, x=10, y=8, w=30)
            except:
                pass
        
        # Add horizontal line
        pdf.set_line_width(0.5)
        pdf.set_draw_color(*style['primary_color'])
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(5)
    
    def _add_pdf_metadata(self, pdf: FPDF, report_data: ReportData, report_config: ReportConfig, style: Dict[str, Any]):
        """Add PDF metadata section"""
        pdf.set_font(style['font_family'], 'B', style['header_font_size'])
        pdf.set_text_color(*style['primary_color'])
        pdf.cell(0, 10, "Report Information", ln=True)
        pdf.ln(5)
        
        pdf.set_font(style['font_family'], '', style['normal_font_size'])
        pdf.set_text_color(0, 0, 0)
        
        # Create metadata table
        metadata = [
            ("Generated", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            ("Report ID", f"SEC-{int(datetime.datetime.now().timestamp())}"),
            ("Format", report_config.format.upper()),
            ("System", report_data.system_info.get('hostname', 'Unknown') if report_data.system_info else 'Unknown'),
            ("Security Score", f"{report_data.scan_results.get('threats_found', 0)} threats detected")
        ]
        
        col_width = 40
        row_height = 8
        
        for label, value in metadata:
            pdf.set_font(style['font_family'], 'B', style['normal_font_size'])
            pdf.cell(col_width, row_height, f"{label}:", border=0)
            pdf.set_font(style['font_family'], '', style['normal_font_size'])
            pdf.cell(0, row_height, str(value), ln=True)
        
        pdf.ln(10)
    
    def _add_pdf_toc(self, pdf: FPDF, report_data: ReportData, style: Dict[str, Any]):
        """Add table of contents"""
        pdf.set_font(style['font_family'], 'B', style['header_font_size'])
        pdf.set_text_color(*style['primary_color'])
        pdf.cell(0, 10, "Table of Contents", ln=True)
        pdf.ln(5)
        
        pdf.set_font(style['font_family'], '', style['normal_font_size'])
        pdf.set_text_color(0, 0, 0)
        
        sections = ["Executive Summary", "System Information", "Scan Results", 
                   "Threat Analysis", "Charts & Statistics", "Recommendations"]
        
        for i, section in enumerate(sections, 1):
            pdf.cell(0, 8, f"{i}. {section}", ln=True)
        
        pdf.ln(10)
    
    def _add_pdf_executive_summary(self, pdf: FPDF, report_data: ReportData, report_config: ReportConfig, style: Dict[str, Any]):
        """Add executive summary"""
        pdf.set_font(style['font_family'], 'B', style['header_font_size'])
        pdf.set_text_color(*style['primary_color'])
        pdf.cell(0, 10, "1. Executive Summary", ln=True)
        pdf.ln(5)
        
        pdf.set_font(style['font_family'], '', style['normal_font_size'])
        pdf.set_text_color(0, 0, 0)
        
        # Generate summary text
        threats_count = report_data.scan_results.get('threats_found', 0)
        security_score = self._calculate_security_score(report_data.scan_results)
        
        summary_text = f"""
        This security report provides a comprehensive analysis of the system's security 
        posture based on recent scans. The system has been evaluated against industry 
        best practices and security benchmarks.
        
        Key Metrics:
        • Overall Security Score: {security_score}/100
        • Threats Detected: {threats_count}
        • Scan Duration: {report_data.scan_results.get('scan_duration', 0):.1f} seconds
        • System Status: {'Secure' if threats_count == 0 else 'Needs Attention'}
        
        The report includes detailed findings, risk assessments, and actionable 
        recommendations to improve the system's security posture.
        """
        
        pdf.multi_cell(0, 6, summary_text.strip())
        pdf.ln(10)
    
    def _add_pdf_system_info(self, pdf: FPDF, system_info: Dict[str, Any], style: Dict[str, Any]):
        """Add system information"""
        pdf.set_font(style['font_family'], 'B', style['header_font_size'])
        pdf.set_text_color(*style['primary_color'])
        pdf.cell(0, 10, "2. System Information", ln=True)
        pdf.ln(5)
        
        pdf.set_font(style['font_family'], '', style['normal_font_size'])
        pdf.set_text_color(0, 0, 0)
        
        if not system_info:
            pdf.cell(0, 8, "No system information available.", ln=True)
            return
        
        # Display key system info
        info_items = [
            ("Hostname", system_info.get('hostname', 'Unknown')),
            ("Operating System", f"Windows {system_info.get('os_version', 'Unknown')}"),
            ("Local IP", system_info.get('local_ip', 'Unknown')),
            ("Public IP", system_info.get('public_ip', 'Unknown') or 'Not available'),
            ("CPU Cores", str(system_info.get('cpu_count', 'Unknown'))),
        ]
        
        col_width = 40
        row_height = 8
        
        for label, value in info_items:
            pdf.set_font(style['font_family'], 'B', style['normal_font_size'])
            pdf.cell(col_width, row_height, f"{label}:", border=0)
            pdf.set_font(style['font_family'], '', style['normal_font_size'])
            pdf.cell(0, row_height, str(value), ln=True)
        
        # Memory info
        if 'memory' in system_info:
            mem = system_info['memory']
            total_gb = mem.get('total', 0) / (1024**3)
            used_percent = mem.get('percent', 0)
            pdf.set_font(style['font_family'], 'B', style['normal_font_size'])
            pdf.cell(col_width, row_height, "Memory:", border=0)
            pdf.set_font(style['font_family'], '', style['normal_font_size'])
            pdf.cell(0, row_height, f"{total_gb:.1f} GB ({used_percent}% used)", ln=True)
        
        pdf.ln(10)
    
    def _add_pdf_scan_results(self, pdf: FPDF, scan_results: Dict[str, Any], style: Dict[str, Any]):
        """Add scan results"""
        pdf.set_font(style['font_family'], 'B', style['header_font_size'])
        pdf.set_text_color(*style['primary_color'])
        pdf.cell(0, 10, "3. Scan Results", ln=True)
        pdf.ln(5)
        
        pdf.set_font(style['font_family'], '', style['normal_font_size'])
        pdf.set_text_color(0, 0, 0)
        
        # Basic scan info
        info_items = [
            ("Scan Type", scan_results.get('scan_type', 'Unknown')),
            ("Timestamp", scan_results.get('timestamp', 'Unknown')),
            ("Duration", f"{scan_results.get('scan_duration', 0):.1f} seconds"),
            ("Threats Found", str(scan_results.get('threats_found', 0))),
            ("Warnings", str(len(scan_results.get('warnings', [])))),
        ]
        
        col_width = 40
        row_height = 8
        
        for label, value in info_items:
            pdf.set_font(style['font_family'], 'B', style['normal_font_size'])
            pdf.cell(col_width, row_height, f"{label}:", border=0)
            pdf.set_font(style['font_family'], '', style['normal_font_size'])
            pdf.cell(0, row_height, str(value), ln=True)
        
        pdf.ln(10)
    
    def _add_pdf_threats(self, pdf: FPDF, threats: List[Dict[str, Any]], style: Dict[str, Any]):
        """Add threats section"""
        if not threats:
            return
        
        pdf.set_font(style['font_family'], 'B', style['header_font_size'])
        pdf.set_text_color(*style['primary_color'])
        pdf.cell(0, 10, "4. Threat Analysis", ln=True)
        pdf.ln(5)
        
        pdf.set_font(style['font_family'], '', style['normal_font_size'])
        pdf.set_text_color(0, 0, 0)
        
        # Count threats by severity
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for threat in threats:
            severity = threat.get('severity', 'low').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Severity summary
        pdf.set_font(style['font_family'], 'B', style['normal_font_size'])
        pdf.cell(0, 8, "Threat Severity Distribution:", ln=True)
        pdf.set_font(style['font_family'], '', style['normal_font_size'])
        
        for severity, count in severity_counts.items():
            if count > 0:
                pdf.cell(0, 8, f"  • {severity.capitalize()}: {count} threats", ln=True)
        
        pdf.ln(10)
        
        # List top threats
        pdf.set_font(style['font_family'], 'B', style['normal_font_size'])
        pdf.cell(0, 8, "Top Threats Detected:", ln=True)
        pdf.set_font(style['font_family'], '', style['normal_font_size'])
        
        for i, threat in enumerate(threats[:10], 1):  # Show top 10
            severity = threat.get('severity', 'low').lower()
            
            # Set color based on severity
            if severity == 'critical':
                pdf.set_text_color(*style['secondary_color'])
            elif severity == 'high':
                pdf.set_text_color(253, 126, 20)  # Orange
            elif severity == 'medium':
                pdf.set_text_color(*style['warning_color'])
            else:
                pdf.set_text_color(*style['success_color'])
            
            pdf.cell(0, 8, f"{i}. {threat.get('name', 'Unknown')} ({severity.upper()})", ln=True)
            pdf.set_text_color(0, 0, 0)
            
            # Add description if space available
            description = threat.get('description', '')
            if description and len(description) < 100:
                pdf.set_font(style['font_family'], 'I', style['small_font_size'])
                pdf.cell(0, 6, f"    {description[:80]}...", ln=True)
                pdf.set_font(style['font_family'], '', style['normal_font_size'])
        
        pdf.ln(10)
    
    def _add_pdf_charts(self, pdf: FPDF, report_data: ReportData, style: Dict[str, Any]):
        """Add charts to PDF"""
        if not CHARTS_AVAILABLE:
            return
        
        try:
            pdf.set_font(style['font_family'], 'B', style['header_font_size'])
            pdf.set_text_color(*style['primary_color'])
            pdf.cell(0, 10, "5. Charts & Statistics", ln=True)
            pdf.ln(5)
            
            # Create threat severity chart
            if report_data.scan_results.get('threats'):
                threats = report_data.scan_results['threats']
                severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
                
                for threat in threats:
                    severity = threat.get('severity', 'low').capitalize()
                    if severity in severity_counts:
                        severity_counts[severity] += 1
                
                # Create pie chart
                fig, ax = plt.subplots(figsize=(6, 4))
                colors = ['#dc3545', '#fd7e14', '#ffc107', '#28a745']
                
                labels = [f"{k} ({v})" for k, v in severity_counts.items() if v > 0]
                sizes = [v for v in severity_counts.values() if v > 0]
                chart_colors = [colors[i] for i, v in enumerate(severity_counts.values()) if v > 0]
                
                if sum(sizes) > 0:
                    ax.pie(sizes, labels=labels, colors=chart_colors, autopct='%1.1f%%', startangle=90)
                    ax.axis('equal')
                    ax.set_title('Threat Severity Distribution')
                    
                    # Save chart to temporary file
                    chart_path = self.output_dir / "temp_chart.png"
                    plt.tight_layout()
                    plt.savefig(chart_path, dpi=150, bbox_inches='tight')
                    plt.close()
                    
                    # Add chart to PDF
                    pdf.image(str(chart_path), x=10, w=180)
                    pdf.ln(5)
                    
                    # Clean up
                    try:
                        os.remove(chart_path)
                    except:
                        pass
            
            pdf.ln(10)
            
        except Exception as e:
            self.logger.error(f"Chart generation failed: {e}")
            pdf.cell(0, 8, "Charts unavailable due to technical error.", ln=True)
    
    def _add_pdf_recommendations(self, pdf: FPDF, recommendations: List[str], style: Dict[str, Any]):
        """Add recommendations section"""
        if not recommendations:
            return
        
        pdf.set_font(style['font_family'], 'B', style['header_font_size'])
        pdf.set_text_color(*style['primary_color'])
        pdf.cell(0, 10, "6. Recommendations", ln=True)
        pdf.ln(5)
        
        pdf.set_font(style['font_family'], '', style['normal_font_size'])
        pdf.set_text_color(0, 0, 0)
        
        for i, rec in enumerate(recommendations[:10], 1):  # Show top 10
            pdf.cell(0, 8, f"{i}. {rec}", ln=True)
        
        pdf.ln(10)
    