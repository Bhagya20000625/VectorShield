from flask import Flask, render_template, jsonify, request, send_file
import os
import glob
import shutil
from datetime import datetime, timedelta
import requests
import xml.etree.ElementTree as ET
import pandas as pd
from pathlib import Path
import json
import ast
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
import html

app = Flask(__name__)

# Configuration
EXCEL_FILES_DIR = 'excel_files'
AUTO_CHECK_DIR = 'Auto_Check'
XML_URL = "https://scsanctions.un.org/resources/xml/en/consolidated.xml"

# Ensure directories exist
os.makedirs(EXCEL_FILES_DIR, exist_ok=True)
os.makedirs(AUTO_CHECK_DIR, exist_ok=True)

def clean_text_for_reportlab(text):
    """Clean text for ReportLab to prevent XML parsing errors"""
    if not text or pd.isna(text):
        return "N/A"
    
    # Convert to string and strip whitespace
    text = str(text).strip()
    
    # If empty after stripping, return N/A
    if not text:
        return "N/A"
    
    # Escape HTML entities first
    text = html.escape(text)
    
    # Replace common problematic characters
    replacements = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&apos;',
        '\n': '<br/>',
        '\r': '',
        '\t': ' ',
    }
    
    for old, new in replacements.items():
        text = text.replace(old, new)
    
    # Remove any remaining non-printable characters
    text = ''.join(char for char in text if ord(char) >= 32 or char in ['\n', '\r', '\t'])
    
    return text if text else "N/A"

class FileManager:
    def __init__(self, directory):
        self.directory = directory
        
    def get_excel_files(self):
        """Get all Excel files in the directory with metadata"""
        files = []
        pattern = os.path.join(self.directory, "*.xlsx")
        
        for file_path in glob.glob(pattern):
            file_info = {
                'name': os.path.basename(file_path),
                'path': file_path,
                'size': self._format_file_size(os.path.getsize(file_path)),
                'modified': datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S'),
                'created': datetime.fromtimestamp(os.path.getctime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
            }
            files.append(file_info)
        
        # Sort by modification time (newest first)
        files.sort(key=lambda x: os.path.getmtime(x['path']), reverse=True)
        return files
    
    def get_file_records_count(self):
        """Get record count for each Excel file (excluding header row)"""
        files_records = {}
        pattern = os.path.join(self.directory, "*.xlsx")
        
        for file_path in glob.glob(pattern):
            try:
                # Read Excel file
                df = pd.read_excel(file_path)
                record_count = len(df)  # This already excludes header row
                
                # Get filename without extension
                filename = os.path.basename(file_path)
                filename_without_ext = os.path.splitext(filename)[0]
                
                files_records[filename_without_ext] = record_count
                
            except Exception as e:
                # If there's an error reading the file, set count to 0
                filename = os.path.basename(file_path)
                filename_without_ext = os.path.splitext(filename)[0]
                files_records[filename_without_ext] = 0
                print(f"Error reading {filename}: {e}")
        
        return files_records
    
    def get_auto_check_files_by_date_range(self, start_date, end_date):
        """Get auto check CSV files within a date range"""
        files = []
        pattern = os.path.join(AUTO_CHECK_DIR, "check_log_*.csv")
        
        try:
            start_dt = datetime.strptime(start_date, '%Y-%m-%d')
            end_dt = datetime.strptime(end_date, '%Y-%m-%d')
        except ValueError:
            return []
        
        for file_path in glob.glob(pattern):
            filename = os.path.basename(file_path)
            # Extract date from filename like check_log_2025-07-26.csv
            try:
                date_part = filename.replace('check_log_', '').replace('.csv', '')
                file_date = datetime.strptime(date_part, '%Y-%m-%d')
                
                if start_dt <= file_date <= end_dt:
                    files.append({
                        'name': filename,
                        'path': file_path,
                        'date': file_date.strftime('%Y-%m-%d')
                    })
            except ValueError:
                continue  # Skip files that don't match the expected format
        
        # Sort by date
        files.sort(key=lambda x: x['date'])
        return files
    
    def _format_file_size(self, size_bytes):
        """Format file size in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"
    
    def clean_old_sanctions_files(self):
        """Remove old sanctions_list files, keeping only the newest"""
        sanctions_files = []
        pattern = os.path.join(self.directory, "sanctions_list_*.xlsx")
        
        for file_path in glob.glob(pattern):
            sanctions_files.append({
                'path': file_path,
                'modified': os.path.getmtime(file_path)
            })
        
        if len(sanctions_files) > 1:
            # Sort by modification time and keep only the newest
            sanctions_files.sort(key=lambda x: x['modified'], reverse=True)
            files_to_delete = sanctions_files[1:]  # All except the newest
            
            deleted_files = []
            for file_info in files_to_delete:
                try:
                    os.remove(file_info['path'])
                    deleted_files.append(os.path.basename(file_info['path']))
                except Exception as e:
                    print(f"Error deleting {file_info['path']}: {e}")
            
            return deleted_files
        return []

    def delete_file(self, filename):
        """Delete a specific file"""
        file_path = os.path.join(self.directory, filename)
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                return True, f"File {filename} deleted successfully"
            except Exception as e:
                return False, f"Error deleting file: {str(e)}"
        return False, "File not found"

def parse_matches(data_str):
    """Parse matches from string data"""
    if pd.isna(data_str) or data_str == '':
        return []

    try:
        data = json.loads(str(data_str))
        if isinstance(data, dict) and 'matches' in data:
            return data['matches']
        elif isinstance(data, list):
            return data
    except:
        pass

    try:
        data = ast.literal_eval(str(data_str))
        if isinstance(data, dict) and 'matches' in data:
            return data['matches']
        elif isinstance(data, list):
            return data
    except:
        pass

    return []

def create_safe_paragraph(text, style):
    """Create a safe paragraph with proper text cleaning"""
    try:
        cleaned_text = clean_text_for_reportlab(text)
        return Paragraph(cleaned_text, style)
    except Exception as e:
        # If there's still an error, return a simple text paragraph
        safe_text = str(text).replace('<', '&lt;').replace('>', '&gt;') if text else "Error displaying text"
        return Paragraph(safe_text, style)

def create_date_range_pdf(start_date, end_date):
    """Create PDF report for date range from Auto_Check folder (CSV files)"""
    try:
        # Get database records count
        files_records = file_manager.get_file_records_count()
        
        # Get auto check files for the date range
        auto_check_files = file_manager.get_auto_check_files_by_date_range(start_date, end_date)
        
        if not auto_check_files:
            return None, "No CSV files found for the specified date range"
        
        # Create PDF filename
        pdf_name = f'sanctions_report_{start_date}_to_{end_date}.pdf'
        doc = SimpleDocTemplate(pdf_name, pagesize=A4, rightMargin=50, leftMargin=50, topMargin=50, bottomMargin=50)

        styles = getSampleStyleSheet()
        title_style = styles['Title']
        heading_style = styles['Heading2']
        normal_style = styles['Normal']

        content = []

        # Title
        content.append(create_safe_paragraph(f"Sanctions Check Report ({start_date} to {end_date})", title_style))
        content.append(Spacer(1, 20))

        # Database Records Summary
        content.append(create_safe_paragraph("Database Records Summary", heading_style))
        content.append(Spacer(1, 10))

        db_data = [['Database Name', 'Record Count']]
        total_db_records = 0
        for db_name, count in files_records.items():
            db_data.append([clean_text_for_reportlab(db_name), str(count)])
            total_db_records += count

        db_data.append(['Total Records', str(total_db_records)])

        db_table = Table(db_data, colWidths=[3*inch, 1.5*inch])
        db_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('BACKGROUND', (0, 1), (-2, -1), colors.lightblue),
            ('BACKGROUND', (-2, -1), (-1, -1), colors.lightgreen),  # Highlight total row
            ('FONTNAME', (-2, -1), (-1, -1), 'Helvetica-Bold')
        ]))

        content.append(db_table)
        content.append(Spacer(1, 30))

        # Process each auto check CSV file
        all_data = []
        total_checks = 0
        total_matches = 0
        total_warnings = 0

        for file_info in auto_check_files:
            try:
                # Read CSV file instead of Excel
                df = pd.read_csv(file_info['path'])
                all_data.append({'date': file_info['date'], 'data': df, 'filename': file_info['name']})
                
                total_checks += len(df)
                total_matches += df['matches_count'].sum() if 'matches_count' in df.columns else 0
                total_warnings += len(df[df['result_message'].str.contains('WARNING', na=False)]) if 'result_message' in df.columns else 0
            except Exception as e:
                print(f"Error reading {file_info['name']}: {e}")

        # Overall Summary
        summary_data = [
            ['Overall Summary', ''],
            ['Date Range', f"{start_date} to {end_date}"],
            ['Files Processed', str(len(auto_check_files))],
            ['Total Checks', str(total_checks)],
            ['Total Matches Found', str(total_matches)],
            ['Warning Cases', str(total_warnings)],
            ['Report Generated', datetime.now().strftime('%Y-%m-%d %H:%M')]
        ]

        summary_table = Table(summary_data, colWidths=[2*inch, 2.5*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey)
        ]))

        content.append(summary_table)
        content.append(Spacer(1, 30))

        # Process data for each day
        check_counter = 1
        for file_data in all_data:
            content.append(create_safe_paragraph(f"Date: {file_data['date']}", heading_style))
            content.append(Spacer(1, 15))

            df = file_data['data']
            
            for idx, row in df.iterrows():
                content.append(create_safe_paragraph(f"Check #{check_counter}: {clean_text_for_reportlab(row.get('input_keyword', 'N/A'))}", heading_style))
                content.append(Spacer(1, 10))

                # Modify status display
                status_value = str(row.get('output_status', 'N/A'))
                if status_value == 'success':
                    status_value = 'matched'

                # Clean all data for the table
                basic_data = [
                    ['Field', 'Value'],
                    ['Keyword Checked', clean_text_for_reportlab(row.get('input_keyword', 'N/A'))],
                    ['Timestamp', clean_text_for_reportlab(row.get('timestamp', 'N/A'))],
                    ['Status', clean_text_for_reportlab(status_value)],
                    ['Result', clean_text_for_reportlab(row.get('result_message', 'N/A'))],
                    ['Matches Found', clean_text_for_reportlab(row.get('matches_count', '0'))]
                ]

                basic_table = Table(basic_data, colWidths=[1.5*inch, 3*inch])
                
                # Create base table style
                table_style = [
                    ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.lightblue)
                ]
                
                # Add color coding for Result row based on content
                result_message = str(row.get('result_message', 'N/A'))
                if 'No Threat, Access Granted' in result_message:
                    # Green background for no threat
                    table_style.append(('BACKGROUND', (0, 4), (-1, 4), colors.lightgreen))
                elif 'WARNING: Match found in List!' in result_message:
                    # Red background for warning
                    table_style.append(('BACKGROUND', (0, 4), (-1, 4), colors.lightcoral))

                basic_table.setStyle(TableStyle(table_style))

                content.append(basic_table)
                content.append(Spacer(1, 15))

                # Parse and display matches
                matches = []
                if 'matches_details' in df.columns:
                    matches = parse_matches(row['matches_details'])
                if not matches and 'full_response' in df.columns:
                    matches = parse_matches(row['full_response'])

                if matches and len(matches) > 0:
                    content.append(create_safe_paragraph("Match Details:", heading_style))
                    content.append(Spacer(1, 5))

                    # Group matches in pairs for side-by-side display
                    for i in range(0, len(matches), 2):
                        match_pair = matches[i:i+2]

                        if len(match_pair) == 2:
                            # Two matches side by side
                            left_match = match_pair[0]
                            right_match = match_pair[1]

                            if isinstance(left_match, dict) and isinstance(right_match, dict):
                                # Create data for both matches
                                left_data = [['Field', 'Value']]
                                right_data = [['Field', 'Value']]

                                important_fields = [
                                    'Name', 'Nationality', 'Date of Birth', 'NIC No. 1', 'NIC No. 2',
                                    'Reference Number', 'UN List Type', 'Listed On', 'Address'
                                ]

                                for field in important_fields:
                                    left_value = left_match.get(field, '')
                                    right_value = right_match.get(field, '')

                                    # Clean and display values
                                    left_display = clean_text_for_reportlab(left_value) if left_value and str(left_value).lower() not in ['nan', 'n/a', ''] else 'Not Available'
                                    right_display = clean_text_for_reportlab(right_value) if right_value and str(right_value).lower() not in ['nan', 'n/a', ''] else 'Not Available'

                                    left_data.append([field, left_display])
                                    right_data.append([field, right_display])

                                # Create side-by-side tables
                                left_table = Table(left_data, colWidths=[0.8*inch, 1.9*inch])
                                right_table = Table(right_data, colWidths=[0.8*inch, 1.9*inch])

                                table_style = TableStyle([
                                    ('BACKGROUND', (0, 0), (-1, 0), colors.red),
                                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                                    ('FONTSIZE', (0, 0), (-1, -1), 7),
                                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                                    ('BACKGROUND', (0, 1), (-1, -1), colors.lightyellow),
                                    ('VALIGN', (0, 0), (-1, -1), 'TOP')
                                ])

                                left_table.setStyle(table_style)
                                right_table.setStyle(table_style)

                                # Combine tables in one row
                                combined_data = [[f"Match {i+1}", f"Match {i+2}"], [left_table, right_table]]
                                combined_table = Table(combined_data, colWidths=[2.7*inch, 2.7*inch])
                                combined_table.setStyle(TableStyle([
                                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                                    ('FONTSIZE', (0, 0), (-1, 0), 9),
                                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                                    ('VALIGN', (0, 0), (-1, -1), 'TOP')
                                ]))

                                content.append(combined_table)
                                content.append(Spacer(1, 5))

                        elif len(match_pair) == 1:
                            # Single match (odd number)
                            match = match_pair[0]
                            if isinstance(match, dict):
                                content.append(create_safe_paragraph(f"Match {i+1}:", normal_style))
                                content.append(Spacer(1, 2))

                                match_data = [['Field', 'Value']]

                                important_fields = [
                                    'Name', 'Nationality', 'Date of Birth', 'NIC No. 1', 'NIC No. 2',
                                    'Reference Number', 'UN List Type', 'Listed On', 'Address'
                                ]

                                for field in important_fields:
                                    value = match.get(field, '')
                                    # Clean and display value
                                    display_value = clean_text_for_reportlab(value) if value and str(value).lower() not in ['nan', 'n/a', ''] else 'Not Available'
                                    match_data.append([field, display_value])

                                if len(match_data) > 1:
                                    match_table = Table(match_data, colWidths=[1.2*inch, 3.3*inch])
                                    match_table.setStyle(TableStyle([
                                        ('BACKGROUND', (0, 0), (-1, 0), colors.red),
                                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                                        ('FONTSIZE', (0, 0), (-1, -1), 8),
                                        ('GRID', (0, 0), (-1, -1), 1, colors.black),
                                        ('BACKGROUND', (0, 1), (-1, -1), colors.lightyellow),
                                        ('VALIGN', (0, 0), (-1, -1), 'TOP')
                                    ]))

                                    content.append(match_table)
                                    content.append(Spacer(1, 3))

                content.append(Spacer(1, 15))
                check_counter += 1

        # Build the document
        doc.build(content)
        print(f"PDF created: {pdf_name}")
        return pdf_name, None
        
    except Exception as e:
        error_msg = f"Error creating PDF: {str(e)}"
        print(error_msg)
        return None, error_msg

def download_xml(url):
    """Download XML file from the URL and save it with a date-stamped filename."""
    today = datetime.now().strftime("%Y%m%d")
    filename = f"consolidated_{today}.xml"
    temp_path = os.path.join("temp", filename)
    
    # Create temp directory if it doesn't exist
    os.makedirs("temp", exist_ok=True)
    
    try:
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            with open(temp_path, "wb") as file:
                file.write(response.content)
            return temp_path
        else:
            return None
    except Exception as e:
        print(f"Error downloading XML: {e}")
        return None

def parse_xml_to_dict(xml_file):
    """Parse the XML file and return a list of dictionaries for Individuals and Entities."""
    if not os.path.exists(xml_file):
        return None

    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"Error parsing XML file: {e}")
        return None

    data = []

    # Process Individuals
    for individual in root.findall('.//INDIVIDUAL'):
        entry = {
            'Type': 'Individual',
            'Data ID': individual.findtext('DATAID', ''),
            'Version Number': individual.findtext('VERSIONNUM', ''),
            'First Name': individual.findtext('FIRST_NAME', ''),
            'Second Name': individual.findtext('SECOND_NAME', ''),
            'Third Name': individual.findtext('THIRD_NAME', ''),
            'UN List Type': individual.findtext('UN_LIST_TYPE', ''),
            'Reference Number': individual.findtext('REFERENCE_NUMBER', ''),
            'Listed On': individual.findtext('LISTED_ON', ''),
            'Original Script Name': individual.findtext('NAME_ORIGINAL_SCRIPT', ''),
            'Comments': individual.findtext('COMMENTS1', ''),
            'Title': ', '.join([t.text for t in individual.findall('TITLE/VALUE') if t.text]),
            'Designation': ', '.join([d.text for d in individual.findall('DESIGNATION/VALUE') if d.text]),
            'Nationality': ', '.join([n.text for n in individual.findall('NATIONALITY/VALUE') if n.text]),
            'Last Updated': ', '.join([u.text for u in individual.findall('LAST_DAY_UPDATED/VALUE') if u.text]),
            'Aliases': ', '.join([a.findtext('ALIAS_NAME', '') for a in individual.findall('INDIVIDUAL_ALIAS') if a.find('ALIAS_NAME') is not None]),
            'Address': ', '.join([f"{a.findtext('COUNTRY', '')} {a.findtext('CITY', '')}".strip() for a in individual.findall('INDIVIDUAL_ADDRESS')]),
            'Date of Birth': f"{individual.findtext('INDIVIDUAL_DATE_OF_BIRTH/TYPE_OF_DATE', '')} {individual.findtext('INDIVIDUAL_DATE_OF_BIRTH/YEAR', '')}".strip(),
            'Place of Birth': f"{individual.findtext('INDIVIDUAL_PLACE_OF_BIRTH/CITY', '')}, {individual.findtext('INDIVIDUAL_PLACE_OF_BIRTH/STATE_PROVINCE', '')}, {individual.findtext('INDIVIDUAL_PLACE_OF_BIRTH/COUNTRY', '')}".strip(', '),
            'Document Number': ', '.join([d.findtext('NUMBER', '') for d in individual.findall('INDIVIDUAL_DOCUMENT') if d.find('NUMBER') is not None])
        }
        data.append(entry)

    # # Process Entities
    # for entity in root.findall('.//ENTITY'):
    #     entry = {
    #         'Type': 'Entity',
    #         'Data ID': entity.findtext('DATAID', ''),
    #         'Version Number': entity.findtext('VERSIONNUM', ''),
    #         'First Name': entity.findtext('FIRST_NAME', ''),
    #         'Second Name': '',
    #         'Third Name': '',
    #         'UN List Type': entity.findtext('UN_LIST_TYPE', ''),
    #         'Reference Number': entity.findtext('REFERENCE_NUMBER', ''),
    #         'Listed On': entity.findtext('LISTED_ON', ''),
    #         'Original Script Name': entity.findtext('NAME_ORIGINAL_SCRIPT', ''),
    #         'Comments': entity.findtext('COMMENTS1', ''),
    #         'Title': '',
    #         'Designation': '',
    #         'Nationality': '',
    #         'Last Updated': ', '.join([u.text for u in entity.findall('LAST_DAY_UPDATED/VALUE') if u.text]),
    #         'Aliases': ', '.join([a.findtext('ALIAS_NAME', '') for a in entity.findall('ENTITY_ALIAS') if a.find('ALIAS_NAME') is not None]),
    #         'Address': ', '.join([f"{a.findtext('STREET', '')}, {a.findtext('CITY', '')}, {a.findtext('STATE_PROVINCE', '')}, {a.findtext('COUNTRY', '')}".strip(', ') for a in entity.findall('ENTITY_ADDRESS')]),
    #         'Date of Birth': '',
    #         'Place of Birth': '',
    #         'Document Number': ''
    #     }
    #     data.append(entry)

    return data

def convert_to_excel(xml_file):
    """Convert the parsed XML data to an Excel file."""
    data = parse_xml_to_dict(xml_file)
    if data is None:
        return None

    df = pd.DataFrame(data)
    
    # Generate filename with current date
    today = datetime.now().strftime("%d%m%Y")
    excel_file = os.path.join(EXCEL_FILES_DIR, f"sanctions_list_{today}.xlsx")
    
    try:
        df.to_excel(excel_file, index=False)
        return excel_file
    except Exception as e:
        print(f"Error writing to Excel file: {e}")
        return None

# Initialize file manager
file_manager = FileManager(EXCEL_FILES_DIR)

# Routes
@app.route('/')
def index():
    return render_template('filemanager.html')

@app.route('/api/files')
def get_files():
    """Get all Excel files in the directory"""
    try:
        files = file_manager.get_excel_files()
        return jsonify({
            'success': True,
            'files': files,
            'count': len(files)
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/files/records_count')
def get_files_records_count():
    """Get record count for each Excel file (excluding header row)"""
    try:
        files_records = file_manager.get_file_records_count()
        return jsonify({
            'success': True,
            'files_records': files_records,
            'total_files': len(files_records)
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/auto_check_files')
def get_auto_check_files():
    """Get all auto check CSV files with their dates"""
    try:
        files = []
        pattern = os.path.join(AUTO_CHECK_DIR, "check_log_*.csv")
        
        for file_path in glob.glob(pattern):
            filename = os.path.basename(file_path)
            # Extract date from filename like check_log_2025-07-26.csv
            try:
                date_part = filename.replace('check_log_', '').replace('.csv', '')
                file_date = datetime.strptime(date_part, '%Y-%m-%d')
                
                files.append({
                    'name': filename,
                    'date': file_date.strftime('%Y-%m-%d'),
                    'size': file_manager._format_file_size(os.path.getsize(file_path)),
                    'modified': datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
                })
            except ValueError:
                continue  # Skip files that don't match the expected format
        
        # Sort by date (newest first)
        files.sort(key=lambda x: x['date'], reverse=True)
        
        return jsonify({
            'success': True,
            'files': files,
            'count': len(files)
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/generate_date_range_report', methods=['POST'])
def generate_date_range_report():
    """Generate PDF report for a date range"""
    try:
        data = request.get_json()
        start_date = data.get('start_date')
        end_date = data.get('end_date')
        
        if not start_date or not end_date:
            return jsonify({
                'success': False,
                'error': 'start_date and end_date are required (format: YYYY-MM-DD)'
            }), 400
        
        # Validate date format
        try:
            datetime.strptime(start_date, '%Y-%m-%d')
            datetime.strptime(end_date, '%Y-%m-%d')
        except ValueError:
            return jsonify({
                'success': False,
                'error': 'Invalid date format. Use YYYY-MM-DD'
            }), 400
        
        pdf_filename, error = create_date_range_pdf(start_date, end_date)
        
        if error:
            return jsonify({
                'success': False,
                'error': error
            }), 500
        
        return jsonify({
            'success': True,
            'message': 'PDF report generated successfully',
            'pdf_filename': pdf_filename,
            'download_url': f'/api/download_report/{pdf_filename}'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/download_report/<filename>')
def download_report(filename):
    """Download generated PDF report"""
    try:
        if os.path.exists(filename):
            return send_file(filename, as_attachment=True)
        else:
            return jsonify({
                'success': False,
                'error': 'Report file not found'
            }), 404
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/update_sanctions')
def update_sanctions():
    """Download new sanctions data and create Excel file"""
    try:
        # Clean old sanctions files first
        deleted_files = file_manager.clean_old_sanctions_files()
        
        # Download XML
        xml_file = download_xml(XML_URL)
        if not xml_file:
            return jsonify({
                'success': False,
                'error': 'Failed to download XML file'
            }), 500
        
        # Convert to Excel
        excel_file = convert_to_excel(xml_file)
        if not excel_file:
            return jsonify({
                'success': False,
                'error': 'Failed to convert XML to Excel'
            }), 500
        
        # Clean up temp XML file
        try:
            os.remove(xml_file)
        except:
            pass
        
        return jsonify({
            'success': True,
            'message': 'Sanctions list updated successfully',
            'new_file': os.path.basename(excel_file),
            'deleted_files': deleted_files
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/delete_file', methods=['POST'])
def delete_file():
    """Delete a specific file"""
    try:
        data = request.get_json()
        filename = data.get('filename')
        
        if not filename:
            return jsonify({
                'success': False,
                'error': 'Filename is required'
            }), 400
        
        success, message = file_manager.delete_file(filename)
        
        return jsonify({
            'success': success,
            'message': message
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/download_file/<filename>')
def download_file(filename):
    """Download a specific file"""
    try:
        file_path = os.path.join(EXCEL_FILES_DIR, filename)
        if os.path.exists(file_path):
            return send_file(file_path, as_attachment=True)
        else:
            return jsonify({
                'success': False,
                'error': 'File not found'
            }), 404
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/reload_excel_files', methods=['POST'])
def reload_excel_files():
    """Reload Excel files endpoint for external calls"""
    try:
        files = file_manager.get_excel_files()
        return jsonify({
            'success': True,
            'message': 'Excel files reloaded successfully',
            'files': files,
            'count': len(files)
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/clean_old_files')
def clean_old_files():
    """Manually trigger cleaning of old sanctions files"""
    try:
        deleted_files = file_manager.clean_old_sanctions_files()
        return jsonify({
            'success': True,
            'message': f'Cleaned {len(deleted_files)} old files',
            'deleted_files': deleted_files
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/upload_files', methods=['POST'])
def upload_files():
    """Upload Excel files to the directory"""
    try:
        if 'files' not in request.files:
            return jsonify({
                'success': False,
                'error': 'No files provided'
            }), 400
        
        files = request.files.getlist('files')
        
        if len(files) == 0:
            return jsonify({
                'success': False,
                'error': 'No files selected'
            }), 400
        
        uploaded_files = []
        errors = []
        
        for file in files:
            if file.filename == '':
                continue
            
            # Check if file is Excel
            if not file.filename.lower().endswith(('.xlsx', '.xls')):
                errors.append(f"{file.filename}: Not an Excel file")
                continue
            
            try:
                # Save file to excel_files directory
                file_path = os.path.join(EXCEL_FILES_DIR, file.filename)
                file.save(file_path)
                uploaded_files.append(file.filename)
            except Exception as e:
                errors.append(f"{file.filename}: {str(e)}")
        
        if len(uploaded_files) == 0:
            return jsonify({
                'success': False,
                'error': 'No files were uploaded. ' + '; '.join(errors)
            }), 400
        
        message = f"Successfully uploaded {len(uploaded_files)} file(s)"
        if errors:
            message += f". {len(errors)} file(s) failed"
        
        return jsonify({
            'success': True,
            'message': message,
            'uploaded_files': uploaded_files,
            'errors': errors if errors else None
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=3031)