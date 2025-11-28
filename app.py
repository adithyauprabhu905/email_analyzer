from flask import Flask, request, render_template, jsonify
import os
import re
import hashlib
from datetime import datetime
from email import policy
from email.parser import BytesParser
import dns.resolver
import mailparser

app = Flask(__name__, static_folder='.', template_folder='.')
MAX_FILE_SIZE = 8 * 1024 * 1024

def extract_email_headers(raw_bytes):
    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    headers = {
        'subject': msg.get('subject', 'N/A'),
        'from': msg.get('from', 'N/A'),
        'to': msg.get('to', 'N/A'),
        'date': msg.get('date', 'N/A'),
        'message_id': msg.get('message-id', 'N/A'),
        'return_path': msg.get('return-path', 'N/A'),
        'received': msg.get_all('received', []),
        'spf': msg.get('received-spf', 'Not found'),
        'dkim': msg.get('dkim-signature', 'Not found'),
        'dmarc': msg.get('authentication-results', 'Not found')
    }
    return headers

def extract_ips_and_urls(raw_bytes):
    text = raw_bytes.decode('utf-8', errors='ignore')
    ips = list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)))
    urls = list(set(re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)))
    emails = list(set(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text)))
    return {'ips': ips[:10], 'urls': urls[:10], 'emails': emails[:10]}

def check_spf_record(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt = rdata.to_text()
            if 'v=spf1' in txt:
                return {'status': 'found', 'record': txt}
        return {'status': 'not_found', 'record': None}
    except Exception as e:
        return {'status': 'error', 'error': str(e)}

def check_dmarc_record(domain):
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        for rdata in answers:
            txt = rdata.to_text()
            if 'v=DMARC1' in txt:
                return {'status': 'found', 'record': txt}
        return {'status': 'not_found', 'record': None}
    except Exception as e:
        return {'status': 'error', 'error': str(e)}

def analyze_attachments(raw_bytes):
    mp = mailparser.parse_from_bytes(raw_bytes)
    attachments = []
    if mp.attachments:
        for att in mp.attachments:
            att_info = {
                'filename': att.get('filename', 'unknown'),
                'content_type': att.get('mail_content_type', 'unknown'),
                'size': len(att.get('payload', b''))
            }
            payload = att.get('payload', b'')
            if payload:
                att_info['md5'] = hashlib.md5(payload).hexdigest()
                att_info['sha256'] = hashlib.sha256(payload).hexdigest()
            suspicious_exts = ['.exe', '.scr', '.bat', '.cmd', '.vbs', '.js', '.jar']
            filename = att_info['filename'].lower()
            att_info['suspicious'] = any(filename.endswith(ext) for ext in suspicious_exts)
            attachments.append(att_info)
    return {'count': len(attachments), 'attachments': attachments}

def generate_risk_score(headers, ips_urls, attachments):
    score = 0
    indicators = []
    
    if 'fail' in str(headers.get('spf', '')).lower():
        score += 30
        indicators.append('SPF Check Failed')
    
    if headers.get('from', '').lower().endswith(('gmail.com', 'outlook.com', 'yahoo.com')):
        score += 10
        indicators.append('Free Email Provider')
    
    if attachments.get('count', 0) > 0:
        for att in attachments.get('attachments', []):
            if att.get('suspicious'):
                score += 40
                indicators.append(f"Suspicious Attachment: {att['filename']}")
    
    if len(ips_urls.get('urls', [])) > 5:
        score += 15
        indicators.append('Multiple URLs Found')
    
    if score >= 60:
        risk_level = 'HIGH'
    elif score >= 30:
        risk_level = 'MEDIUM'
    else:
        risk_level = 'LOW'
    
    return {'score': min(score, 100), 'level': risk_level, 'indicators': indicators}

@app.route('/')
def index():
    return render_template('face.html')

@app.route('/analyze_email', methods=['POST'])
def analyze_email():
    if 'email_file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    f = request.files['email_file']
    if f.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    data = f.read()
    if len(data) > MAX_FILE_SIZE:
        return jsonify({'error': 'File too large (max 8MB)'}), 400
    
    headers = extract_email_headers(data)
    ips_urls = extract_ips_and_urls(data)
    attachments = analyze_attachments(data)
    
    from_email = headers.get('from', '')
    domain_match = re.search(r'@([a-zA-Z0-9.-]+)', from_email)
    domain = domain_match.group(1) if domain_match else None
    
    dns_checks = {}
    if domain:
        dns_checks['spf'] = check_spf_record(domain)
        dns_checks['dmarc'] = check_dmarc_record(domain)
    
    risk = generate_risk_score(headers, ips_urls, attachments)
    
    results = {
        'headers': headers,
        'ips_urls': ips_urls,
        'attachments': attachments,
        'dns_checks': dns_checks,
        'risk': risk,
        'domain': domain,
        'timestamp': datetime.now().isoformat()
    }
    
    return jsonify(results)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
