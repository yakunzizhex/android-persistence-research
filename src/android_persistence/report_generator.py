"""
Report Generator - Generate comprehensive analysis reports in multiple formats.

Generates detailed findings reports in JSON, PDF, and HTML formats with
visualizations, statistics, and executive summaries.

Author: Security Research Team
License: Apache-2.0
"""

import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
from dataclasses import asdict

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
except ImportError:
    SimpleDocTemplate = None


class ReportGenerator:
    """
    Generate comprehensive analysis reports.
    
    Supports multiple output formats:
    - JSON: Machine-readable findings
    - HTML: Interactive web-based reports
    - PDF: Professional printable reports
    
    Example:
        >>> generator = ReportGenerator()
        >>> generator.generate_report(findings, "report.json")
    """

    def __init__(self, title: str = "Android Persistence Analysis Report"):
        """
        Initialize report generator.
        
        Args:
            title: Report title
        """
        self.title = title
        self.timestamp = datetime.now()
        self.findings: List[Dict[str, Any]] = []

    def add_findings(self, findings: List[Any]) -> None:
        """
        Add findings to report.
        
        Args:
            findings: List of finding objects
        """
        for finding in findings:
            if hasattr(finding, 'to_dict'):
                self.findings.append(finding.to_dict())
            elif isinstance(finding, dict):
                self.findings.append(finding)

    def generate_json_report(self, output_path: str) -> bool:
        """
        Generate JSON format report.
        
        Args:
            output_path: Output file path
            
        Returns:
            True if generation succeeded
        """
        try:
            report_data = {
                "title": self.title,
                "timestamp": self.timestamp.isoformat(),
                "total_findings": len(self.findings),
                "findings": self.findings,
                "statistics": self._calculate_statistics(),
            }

            with open(output_path, 'w') as f:
                json.dump(report_data, f, indent=2, default=str)

            print(f"JSON report generated: {output_path}")
            return True
        except Exception as e:
            print(f"Error generating JSON report: {str(e)}")
            return False

    def generate_html_report(self, output_path: str) -> bool:
        """
        Generate HTML format report.
        
        Args:
            output_path: Output file path
            
        Returns:
            True if generation succeeded
        """
        try:
            html_content = self._generate_html_content()

            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)

            print(f"HTML report generated: {output_path}")
            return True
        except Exception as e:
            print(f"Error generating HTML report: {str(e)}")
            return False

    def generate_pdf_report(self, output_path: str) -> bool:
        """
        Generate PDF format report.
        
        Args:
            output_path: Output file path
            
        Returns:
            True if generation succeeded
        """
        if SimpleDocTemplate is None:
            print("Error: reportlab not installed. Install with: pip install reportlab")
            return False

        try:
            doc = SimpleDocTemplate(output_path, pagesize=letter)
            story = []
            styles = getSampleStyleSheet()

            # Title
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#FF0000'),
                spaceAfter=30,
            )
            story.append(Paragraph(self.title, title_style))
            story.append(Spacer(1, 0.3*inch))

            # Summary
            stats = self._calculate_statistics()
            summary_text = f"""
            <b>Report Generated:</b> {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}<br/>
            <b>Total Findings:</b> {stats['total_findings']}<br/>
            <b>Critical:</b> {stats['critical']} | 
            <b>High:</b> {stats['high']} | 
            <b>Medium:</b> {stats['medium']} | 
            <b>Low:</b> {stats['low']}
            """
            story.append(Paragraph(summary_text, styles['Normal']))
            story.append(Spacer(1, 0.3*inch))

            # Findings table
            if self.findings:
                table_data = [['Type', 'Component', 'Severity', 'Confidence']]
                for finding in self.findings[:20]:  # Limit to 20 per page
                    table_data.append([
                        finding.get('persistence_type', 'Unknown'),
                        finding.get('component_name', 'N/A')[:20],
                        finding.get('severity', 'N/A'),
                        f"{finding.get('confidence', 0)}%",
                    ])

                table = Table(table_data)
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#FF0000')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 12),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ]))
                story.append(table)

            doc.build(story)
            print(f"PDF report generated: {output_path}")
            return True
        except Exception as e:
            print(f"Error generating PDF report: {str(e)}")
            return False

    def _generate_html_content(self) -> str:
        """Generate HTML report content."""
        stats = self._calculate_statistics()
        
        severity_colors = {
            'CRITICAL': '#FF0000',
            'HIGH': '#FF6600',
            'MEDIUM': '#FFCC00',
            'LOW': '#00CC00',
            'INFO': '#0066FF',
        }

        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>{self.title}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
                .header {{ background-color: #333; color: white; padding: 20px; border-radius: 5px; }}
                .summary {{ background-color: white; padding: 20px; margin: 20px 0; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
                .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin: 20px 0; }}
                .stat-box {{ background-color: white; padding: 20px; border-radius: 5px; text-align: center; border-left: 5px solid #333; }}
                .finding {{ background-color: white; padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 5px solid #999; }}
                .critical {{ border-left-color: {severity_colors['CRITICAL']}; }}
                .high {{ border-left-color: {severity_colors['HIGH']}; }}
                .medium {{ border-left-color: {severity_colors['MEDIUM']}; }}
                .low {{ border-left-color: {severity_colors['LOW']}; }}
                .severity {{ display: inline-block; padding: 5px 10px; border-radius: 3px; font-weight: bold; color: white; }}
                table {{ width: 100%; border-collapse: collapse; background-color: white; margin: 20px 0; }}
                th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #333; color: white; }}
                tr:hover {{ background-color: #f5f5f5; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>{self.title}</h1>
                <p>Generated: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="summary">
                <h2>Executive Summary</h2>
                <p>This report presents findings from comprehensive Android APK persistence analysis.</p>
            </div>
            
            <div class="stats">
                <div class="stat-box">
                    <h3>{stats['total_findings']}</h3>
                    <p>Total Findings</p>
                </div>
                <div class="stat-box">
                    <h3 style="color: {severity_colors['CRITICAL']}">{stats['critical']}</h3>
                    <p>Critical</p>
                </div>
                <div class="stat-box">
                    <h3 style="color: {severity_colors['HIGH']}">{stats['high']}</h3>
                    <p>High</p>
                </div>
                <div class="stat-box">
                    <h3 style="color: {severity_colors['MEDIUM']}">{stats['medium']}</h3>
                    <p>Medium</p>
                </div>
            </div>
            
            <h2>Findings</h2>
            <table>
                <tr>
                    <th>Type</th>
                    <th>Component</th>
                    <th>Severity</th>
                    <th>Confidence</th>
                    <th>Description</th>
                </tr>
        """

        for finding in self.findings:
            severity = finding.get('severity', 'UNKNOWN')
            severity_class = severity.lower()
            color = severity_colors.get(severity, '#999999')
            
            html += f"""
                <tr>
                    <td>{finding.get('persistence_type', 'Unknown')}</td>
                    <td>{finding.get('component_name', 'N/A')}</td>
                    <td><span class="severity" style="background-color: {color}">{severity}</span></td>
                    <td>{finding.get('confidence', 0)}%</td>
                    <td>{finding.get('description', 'N/A')[:100]}...</td>
                </tr>
            """

        html += """
            </table>
            
            <div class="summary">
                <h2>Disclaimer</h2>
                <p><strong>RESEARCH ONLY:</strong> This tool is designed for legitimate security research 
                and defensive analysis only. Unauthorized analysis of applications without permission may 
                violate laws and ethical standards. Use only on systems where you have proper authorization.</p>
            </div>
        </body>
        </html>
        """

        return html

    def _calculate_statistics(self) -> Dict[str, Any]:
        """Calculate report statistics."""
        stats = {
            'total_findings': len(self.findings),
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
        }

        for finding in self.findings:
            severity = finding.get('severity', '').upper()
            if severity in stats:
                stats[severity] += 1

        return stats

    def print_summary(self) -> None:
        """Print summary to console."""
        stats = self._calculate_statistics()
        print("\n" + "="*70)
        print("REPORT SUMMARY")
        print("="*70)
        print(f"Title: {self.title}")
        print(f"Generated: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"\nTotal Findings: {stats['total_findings']}")
        print(f"  Critical: {stats['critical']}")
        print(f"  High: {stats['high']}")
        print(f"  Medium: {stats['medium']}")
        print(f"  Low: {stats['low']}")
        print("="*70 + "\n")
