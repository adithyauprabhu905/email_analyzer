# Email Forensics Analyzer

A sophisticated web-based email forensics tool designed to analyze .eml email files and detect suspicious indicators for cybersecurity investigations.

## Features

### 🔍 **Email Analysis Capabilities**
- **Header Analysis**: Extracts and analyzes email headers including SPF, DMARC, and authentication records
- **IP & URL Detection**: Identifies and extracts IP addresses and URLs from email content
- **Attachment Analysis**: Scans for suspicious file attachments and their characteristics
- **Risk Scoring**: Generates automated risk scores based on multiple threat indicators

### 🛡️ **Security Indicators**
- SPF (Sender Policy Framework) validation
- DMARC (Domain-based Message Authentication) checks
- Free email provider detection
- Suspicious attachment identification
- Multiple URL flagging
- Risk level classification (LOW/MEDIUM/HIGH)

### 🎨 **User Interface**
- Modern, futuristic dark theme with neon accents
- Drag-and-drop file upload functionality
- Real-time analysis feedback
- Detailed forensic report display
- Responsive design for all devices

## Installation

### Prerequisites
- Python 3.7+
- pip (Python package manager)

### Setup
1. **Clone or navigate to the email directory**
   ```bash
   cd email/
   ```

2. **Install required dependencies**
   ```bash
   pip install flask dnspython mailparser
   ```

3. **Run the application**
   ```bash
   python app.py
   ```

4. **Access the application**
   Open your web browser and navigate to `http://localhost:5000`

## Usage

### Analyzing an Email
1. **Upload Email File**: Click the upload area or drag-and-drop a `.eml` file
2. **Start Analysis**: Click the "Analyze Email" button
3. **Review Results**: Examine the comprehensive forensic report including:
   - Email headers and metadata
   - Extracted IP addresses and URLs
   - Attachment analysis
   - DNS security checks
   - Risk assessment with threat indicators

### Supported File Formats
- `.eml` (Email Message Format)
- `.txt` (Plain text email files)

### File Size Limits
- Maximum file size: 8MB

## Technical Details

### Core Components

#### [`app.py`](email/app.py)
Main Flask application containing:
- **Email header extraction and parsing**
- **IP/URL pattern recognition**
- **SPF/DMARC DNS validation**
- **Attachment security analysis**
- **Risk scoring algorithm**

#### [`face.html`](email/face.html)
Frontend interface featuring:
- **Responsive web design**
- **File upload handling**
- **Real-time analysis feedback**
- **Result visualization**

### Analysis Functions

#### Header Analysis ([`extract_email_headers`](email/app.py))
Extracts critical email headers including authentication records, routing information, and metadata.

#### Network Analysis ([`extract_ips_and_urls`](email/app.py))
Uses regex patterns to identify IP addresses and URLs embedded in email content.

#### DNS Security Checks
- **SPF Validation** ([`check_spf_record`](email/app.py)): Verifies sender authorization
- **DMARC Policy Check** ([`check_dmarc_record`](email/app.py)): Validates domain authentication policies

#### Risk Assessment ([`generate_risk_score`](email/app.py))
Calculates threat scores based on:
- Failed SPF checks (+30 points)
- Free email providers (+10 points)
- Suspicious attachments (+40 points)
- Multiple URLs (+15 points)

## API Endpoints

### `GET /`
Serves the main application interface

### `POST /analyze_email`
Processes uploaded email files and returns forensic analysis results

**Request Format:**
```
Content-Type: multipart/form-data
Field: email_file (file upload)
```

**Response Format:**
```json
{
  "headers": {...},
  "ips_urls": {...},
  "attachments": {...},
  "dns_checks": {...},
  "risk_assessment": {
    "score": 0-100,
    "level": "LOW|MEDIUM|HIGH",
    "indicators": [...]
  }
}
```

## Security Features

### Input Validation
- File type verification
- Size limit enforcement (8MB max)
- Malicious content scanning

### DNS Security
- Real-time SPF record validation
- DMARC policy verification
- Domain reputation analysis

### Attachment Analysis
- File extension analysis
- Suspicious pattern detection
- Content type verification

## Use Cases

### 🔒 **Cybersecurity Investigations**
- Phishing email analysis
- Social engineering detection
- Email-based threat hunting

### 📧 **Email Authentication**
- SPF/DMARC compliance verification
- Sender reputation analysis
- Authentication bypass detection

### 🕵️ **Digital Forensics**
- Email metadata extraction
- Communication pattern analysis
- Evidence collection and documentation

## Contributing

Contributions are welcome! Please ensure your code follows the existing style and includes appropriate security considerations for handling potentially malicious email content.

## License

This project is designed for educational and cybersecurity research purposes. Use responsibly and in accordance with applicable laws and regulations.

---

**⚠️ Security Notice**: This tool is designed to analyze potentially malicious email content. Always run in a secure, isolated environment when analyzing suspicious emails.
