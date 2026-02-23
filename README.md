# VectorShield - Backend API

🛡️ Advanced sanctions screening backend with fuzzy name matching capabilities.

## Overview

This is the **backend API** for VectorShield. The frontend is built separately using React.js.

## Features

- ✅ **Fuzzy Name Matching** - 80% similarity threshold using RapidFuzz
- ✅ **Hash-based Exact Matching** - Lightning-fast exact searches
- ✅ **Batch File Upload** - Process CSV/Excel files with multiple records
- ✅ **Multi-stage Search** - Three filtering stages for different use cases
- ✅ **PDF/Excel Export** - Generate comprehensive reports
- ✅ **Analytics & Risk Scoring** - Automated risk assessment
- ✅ **REST API** - `/check` endpoint for external integrations

## Tech Stack

**Backend:**
- Flask (Python web framework)
- RapidFuzz (Fuzzy string matching)
- Pandas (Data processing)
- ReportLab (PDF generation)
- OpenPyXL (Excel generation)

## Installation

### Prerequisites
- Python 3.8+
- pip

### Setup

1. Clone the repository:
```bash
git clone <your-repo-url>
cd <repo-name>
```

2. Create virtual environment:
```bash
python -m venv .venv
.venv\Scripts\activate  # Windows
# or
source .venv/bin/activate  # Linux/Mac
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Create required folders:
```bash
mkdir Excel_files uploads Auto_Check
```

5. Add your sanctions database Excel files to `Excel_files/` folder

## Running the Application

Start the Flask API server:
```bash
python TC.py
```

The API server will be available at `http://localhost:5000`

**Note:** This is a backend API only. You'll need to run the React frontend separately to access the UI.

## Configuration

- **Port:** 5000 (default)
- **Fuzzy Threshold:** 80% (fixed)
- **Max Workers:** 4 (for batch processing)

## API Endpoints

### `POST /check` - Quick sanctions check
Quick API endpoint for checking a single name/keyword.

**Request:**
```json
{
  "keyword": "John Doe"
}
```

**Response:**
```json
{
  "result_message": "WARNING: Match found in List!",
  "matched_term": "john doe",
  "matches": [...],
  "status": "success"
}
```

### `POST /` - Manual search
Manual search with optional field filtering.

### `POST /generate_pdf` - Generate PDF report
Generate PDF report from search results.

### `POST /generate_excel` - Generate Excel report  
Generate Excel report with analytics and visualizations.

### `POST /analyze_data` - Get analytics
Get detailed analytics and risk scoring for search results.

## Project Structure

```
VectorShield-Backend/
├── TC.py                    # Main Flask API server
├── filemanager.py          # Database management app
├── Excel_files/            # Sanctions database (gitignored)
├── uploads/                # User uploads (gitignored)
├── requirements.txt        # Python dependencies
├── .gitignore             # Git ignore rules
└── README.md              # This file
```

## Frontend

The React.js frontend is maintained in a separate repository:
- Repository: [Coming soon]
- Documentation: [Coming soon]

## Roadmap

### In Progress
- [ ] React.js frontend (separate repository)

### Planned
- [ ] GPU acceleration with CuPy
- [ ] Advanced tokenization for alphanumeric IDs
- [ ] Dual index system for faster API responses
- [ ] Docker containerization
- [ ] API rate limiting
- [ ] Authentication & authorization
- [ ] WebSocket support for real-time updates

## License

[Add your license here]

## Contributing

[Add contribution guidelines]

## Contact

[Add your contact information]
