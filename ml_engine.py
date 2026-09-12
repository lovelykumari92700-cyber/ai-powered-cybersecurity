import os
import pickle
import re
import json
# pyrefly: ignore [missing-import]
import numpy as np

# Automatically train models if they do not exist
MODELS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'models')
VECTORIZER_PATH = os.path.join(MODELS_DIR, 'vectorizer.pkl')
DEFAULT_MODEL_PATH = os.path.join(MODELS_DIR, 'logistic_regression.pkl')

def ensure_models_trained():
    if not os.path.exists(VECTORIZER_PATH) or not os.path.exists(DEFAULT_MODEL_PATH):
        print("Models not found. Training models on startup...")
        from train_models import train_and_evaluate
        train_and_evaluate()

# Dictionary of keyword categories and descriptions for text analysis
RED_FLAG_PATTERNS = {
    'Urgent language': {
        'patterns': [r'\b(immediately|urgent|urgently|action required|within 24 hours|asap|soon as possible|act now)\b', r'\b(expire|expires|expiring|final warning|last chance)\b'],
        'desc': 'Creates a false sense of urgency to force quick, unthinking decisions.'
    },
    'Threatening messages': {
        'patterns': [r'\b(arrest|police|court|prosecution|penalty|suspended|locked|blocked|frozen|legal action|lawsuit)\b'],
        'desc': 'Threatens legal action, account suspension, or fines to induce fear and compliance.'
    },
    'Prize-winning claims': {
        'patterns': [r'\b(won|winner|lottery|prize|jackpot|selected|raffle|giveaway|cash reward|free gift|million)\b'],
        'desc': 'Claims you have won money or a prize to lure you into paying processing fees or sharing details.'
    },
    'OTP requests': {
        'patterns': [r'\b(otp|verification code|security code|authorization code|one-time password|verification pin|auth code)\b'],
        'desc': 'Requests secret temporary access codes to bypass multi-factor authentication and hijack accounts.'
    },
    'Password requests': {
        'patterns': [r'\b(password|passcode|secret pin|credentials|login details|sign-in details|security pin)\b'],
        'desc': 'Directly asks for authentication credentials to compromise your digital identity.'
    },
    'Bank detail requests': {
        'patterns': [r'\b(bank account|credit card|debit card|routing number|card details|billing update|cvv|account details)\b'],
        'desc': 'Requests banking identifiers or card verification keys to execute unauthorized transfers.'
    },
    'Unrealistic salary offers': {
        'patterns': [r'\b(earn \$[0-9,]+ (daily|weekly|a day|a week))\b', r'\b(work from home part-time|part-time recruiting|no experience required)\b', r'\b(\$[0-9]+/hour from home)\b'],
        'desc': 'Promises high pay for trivial remote tasks, typical of identity theft or payment scams.'
    },
    'Investment promises': {
        'patterns': [r'\b(double your (bitcoin|crypto|money|cash))\b', r'\b(guaranteed returns|get rich quick|passive income guaranteed|roi|500% return|compound yield)\b'],
        'desc': 'Promises guaranteed high yields with zero risk, indicating Ponzi or exit scam schemes.'
    },
    'Limited-time pressure tactics': {
        'patterns': [r'\b(hurry|limited quantity|seconds left|valid for 5 minutes|claim within 48 hours|don\'t wait)\b'],
        'desc': 'Exerts temporal pressure to stop you from validating the claim or consulting others.'
    },
    'Suspicious links': {
        'patterns': [r'https?://[^\s]+'],
        'desc': 'Redirects to unofficial, obfuscated, or custom-crafted domain names designed to look authentic.'
    }
}

# Recommendations based on threat category
SECURITY_RECOMMENDATIONS = {
    'OTP Scam': [
        "Never share One-Time Passwords (OTP) with anyone. Support agents will never ask for them.",
        "Enable authenticator-app-based MFA (like Google Authenticator) instead of SMS OTP where possible.",
        "If you received an unsolicited OTP, it means someone already knows your password. Change it immediately."
    ],
    'Banking Scam': [
        "Do not click on links in SMS or email claiming to unlock your bank account.",
        "Always call the official customer service number on the back of your debit/credit card to verify alerts.",
        "Banks will never ask you to verify your full SSN, PIN, or password over text or phone calls."
    ],
    'Job Scam': [
        "Research the hiring organization. Verify the recruiter through official company directories or LinkedIn.",
        "Never pay upfront fees for 'training materials', 'onboarding software', or 'work laptops'.",
        "Be highly suspicious of recruiters communicating solely via Telegram, WhatsApp, or signal messenger."
    ],
    'Lottery Scam': [
        "Remember: You cannot win a lottery or raffle that you did not enter.",
        "Legitimate lotteries never require winners to pay transaction, clearance, or tax fees upfront to claim prizes.",
        "Do not provide personal mailing addresses or bank details to claim 'free giveaways'."
    ],
    'Investment Scam': [
        "Always remember: High returns equal high risk. 'Guaranteed returns' do not exist in regulated markets.",
        "Check if the investment firm is registered with financial authorities (like SEC, FCA, or local regulators).",
        "Avoid crypto schemes promoted by direct messages on social media or strangers offering trading guidance."
    ],
    'Loan Scam': [
        "Legitimate lenders never request upfront 'activation fees', 'insurance fees', or 'processing charges'.",
        "Be cautious of loans that offer 'guaranteed approval' without checking credit history or financial status.",
        "Always read the loan agreement details and verify the physical location and credentials of the lender."
    ],
    'Prize Scam': [
        "Watch out for shipping fees. Fraudulent sites claim you won a prize but require a $1 fee to input credit card details.",
        "Do not take surveys that offer high value rewards ($100+ gift cards) in exchange for detailed personal information.",
        "Check the official store's website directly rather than following links from random promo codes."
    ],
    'Phishing Scam': [
        "Verify the email sender address and full domain name. Phishers use domain lookalikes (e.g., netflx-billing.com).",
        "Use a password manager, which will not auto-fill details on spoofed website domains.",
        "Hover over links to verify the actual URL path before clicking."
    ],
    'Safe': [
        "This message appears to be safe and legitimate.",
        "Continue exercising standard digital safety hygiene.",
        "Report any sudden change in messaging topics or requests for personal info even from trusted contacts."
    ],
    'Unknown Risk': [
        "Treat this message with caution as its intent could not be verified with high confidence.",
        "Do not click links or share confidential information.",
        "Cross-check claims through independent channels (e.g. search official web addresses)."
    ]
}

def analyze_text(text, model_name='Logistic Regression'):
    ensure_models_trained()
    
    # Pre-check for empty inputs
    if not text or not text.strip():
        return {
            'text': '',
            'risk_score': 0,
            'confidence': 100,
            'threat_level': 'Safe',
            'category': 'Safe',
            'red_flags': [],
            'highlighted_text': '',
            'recommendations': SECURITY_RECOMMENDATIONS['Safe']
        }
        
    # Load vectorizer and chosen model
    with open(VECTORIZER_PATH, 'rb') as f:
        vectorizer = pickle.load(f)
        
    model_filename = model_name.lower().replace(' ', '_') + '.pkl'
    model_path = os.path.join(MODELS_DIR, model_filename)
    
    # Fallback to logistic regression if selected model is missing
    if not os.path.exists(model_path):
        model_path = DEFAULT_MODEL_PATH
        model_name = 'Logistic Regression'
        
    with open(model_path, 'rb') as f:
        model = pickle.load(f)
        
    # Vectorize input
    vec_text = vectorizer.transform([text])
    
    # Predict probabilities and label
    probs = model.predict_proba(vec_text)[0]
    classes = model.classes_
    
    pred_idx = np.argmax(probs)
    category = classes[pred_idx]
    confidence = round(float(probs[pred_idx]) * 100, 2)
    
    # Red flag rules analysis
    detected_flags = []
    highlighted_text = text
    
    # Track character replacements to avoid highlighting inside already highlighted sections
    # We will do a simple regex find and highlight, marking matched spans
    matches_found = []
    
    for category_name, info in RED_FLAG_PATTERNS.items():
        found_in_category = False
        for pattern in info['patterns']:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                start, end = match.span()
                val = match.group()
                matches_found.append((start, end, val, category_name, info['desc']))
                found_in_category = True
        
        if found_in_category:
            detected_flags.append({
                'name': category_name,
                'description': info['desc']
            })
            
    # Sort matches by start index descending to safely replace without breaking offsets
    matches_found = sorted(matches_found, key=lambda x: x[0], reverse=True)
    
    # Remove overlapping matches
    filtered_matches = []
    last_start = len(text) + 1
    for m in matches_found:
        start, end, val, cat_name, desc = m
        if end <= last_start:
            filtered_matches.append(m)
            last_start = start
            
    # Apply highlighting
    for start, end, val, cat_name, desc in filtered_matches:
        highlighted_text = (
            highlighted_text[:start] +
            f'<span class="flag-highlight" data-bs-toggle="tooltip" data-bs-placement="top" title="{cat_name}: {desc}">{highlighted_text[start:end]}</span>' +
            highlighted_text[end:]
        )
        
    # Calculate a combined hybrid Risk Score
    # Starting base score is model confidence for scam class, or low score if Safe
    if category == 'Safe':
        base_score = max(0, 100 - confidence) # Safe with 95% confidence -> 5% risk
    else:
        base_score = confidence # Scam with 80% confidence -> 80% base risk
        
    # Modify risk based on amount of rules flags detected
    # Each high severity flag (OTP, Password, Bank Details, Suspicious Link) adds weights
    weight_adder = 0
    high_severity_flags = ['OTP requests', 'Password requests', 'Bank detail requests', 'Suspicious links', 'Urgent language']
    for flag in detected_flags:
        if flag['name'] in high_severity_flags:
            weight_adder += 15
        else:
            weight_adder += 8
            
    # Ensure risk score goes up if scam class is predicted, and scales down if Safe
    if category != 'Safe':
        risk_score = min(100, int(base_score + weight_adder))
        # Override to ensure it is at least a minimum threshold for classified scams
        risk_score = max(risk_score, 60)
    else:
        # If model says safe, but we have multiple high severity flags, force risk level to increase
        if len(detected_flags) >= 2:
            category = 'Unknown Risk'
            risk_score = min(75, 20 + weight_adder)
        else:
            risk_score = max(0, int(base_score - (10 if len(detected_flags) == 0 else 0)))
            risk_score = min(risk_score, 35) # Max risk for safe is 35% unless forced
            
    # Classify Threat Level
    if risk_score <= 15:
        threat_level = 'Safe'
    elif risk_score <= 40:
        threat_level = 'Low Risk'
    elif risk_score <= 65:
        threat_level = 'Medium Risk'
    elif risk_score <= 88:
        threat_level = 'High Risk'
    else:
        threat_level = 'Critical Risk'
        
    # Fallback recommendations
    recs = SECURITY_RECOMMENDATIONS.get(category, SECURITY_RECOMMENDATIONS['Unknown Risk'])
    
    return {
        'text': text,
        'risk_score': risk_score,
        'confidence': confidence,
        'threat_level': threat_level,
        'category': category,
        'red_flags': detected_flags,
        'highlighted_text': highlighted_text,
        'recommendations': recs
    }

def analyze_url(url):
    if not url or not url.strip():
        return {
            'url': '',
            'risk_score': 0,
            'threat_level': 'Safe',
            'confidence': 100,
            'indicators': [],
            'explanation': 'No URL provided for analysis.'
        }
        
    url = url.strip()
    
    # Match schema or append temporary http for parsing
    working_url = url
    if not url.startswith('http://') and not url.startswith('https://'):
        working_url = 'http://' + url
        
    # Basic URL parsing features
    indicators = []
    risk_score = 10
    
    # 1. HTTPS availability
    has_https = url.startswith('https://')
    if not has_https:
        risk_score += 20
        indicators.append({
            'name': 'Unencrypted Protocol (HTTP)',
            'severity': 'Medium',
            'desc': 'The connection uses plain HTTP. Traffic can be intercepted, and phishing sites rarely support legitimate SSL.'
        })
        
    # Extract Domain
    domain = ""
    domain_match = re.search(r'https?://([^/\s?#]+)', working_url)
    if domain_match:
        domain = domain_match.group(1)
        
    # 2. URL Length
    url_len = len(url)
    if url_len > 75:
        risk_score += 15
        indicators.append({
            'name': 'Excessive URL Length',
            'severity': 'Low',
            'desc': f'The URL is very long ({url_len} characters). Attackers use long URLs to hide suspicious subdomain directories from view.'
        })
        
    # 3. IP-based URLs
    # Check for IPv4 addresses in the domain
    ip_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]+)?$'
    if re.match(ip_pattern, domain):
        risk_score += 35
        indicators.append({
            'name': 'IP-Address Domain Host',
            'severity': 'High',
            'desc': f'The URL points directly to an IP address ({domain}) instead of a registered domain name. This is a common tactic for hosting rapid, temporary scam servers.'
        })
        
    # 4. Subdomains count
    # Split domain by dots. For example, login.verify.bank.com has parts ['login', 'verify', 'bank', 'com'] -> length 4
    domain_parts = domain.split('.')
    # Strip www
    if 'www' in domain_parts:
        domain_parts.remove('www')
    if len(domain_parts) > 3:
        risk_score += 15
        indicators.append({
            'name': 'Excessive Subdomains',
            'severity': 'Medium',
            'desc': f'The URL uses {len(domain_parts) - 2} levels of subdomains. Attackers pad subdomains with terms like "secure" or "login" to masquerade as trust brands.'
        })
        
    # 5. Suspicious keywords in URL (both domain and path)
    suspicious_url_keywords = ['login', 'signin', 'verify', 'verification', 'secure', 'bank', 'billing', 'update', 'account', 'recovery', 'webscr', 'portal', 'paypal', 'netflix', 'amazon', 'facebook', 'google', 'chase', 'wellsfargo', 'dhl', 'ups']
    found_keywords = []
    lower_url = url.lower()
    for kw in suspicious_url_keywords:
        # Check if keyword is inside path or in subdomains, but not the primary domain name (simplistic check)
        if kw in lower_url:
            # Let's verify it is not the main registered domain to avoid false positives (e.g. google.com has 'google')
            if len(domain_parts) >= 2:
                primary_domain = '.'.join(domain_parts[-2:])
                if kw in primary_domain:
                    continue # Skip if it belongs to the main domain
            found_keywords.append(kw)
            
    if found_keywords:
        risk_score += min(30, len(found_keywords) * 10)
        indicators.append({
            'name': 'Credential/Brand Keyword Spoofing',
            'severity': 'High',
            'desc': f'Found keyword indicators {found_keywords} embedded in the URL path/subdomain, which mimic official access points.'
        })
        
    # 6. URL Shorteners
    shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'buff.ly', 'ow.ly']
    is_shortener = False
    for s in shorteners:
        if s in domain.lower():
            is_shortener = True
            break
            
    if is_shortener:
        risk_score += 25
        indicators.append({
            'name': 'URL Redirection Shortener',
            'severity': 'Medium',
            'desc': 'Uses a shortener service. This conceals the destination domain, hiding potential threats from user view before clicking.'
        })
        
    # 7. Special characters in domain
    special_chars = re.findall(r'[-@?=_]', domain)
    if len(special_chars) > 1:
        risk_score += 15
        indicators.append({
            'name': 'Excessive Special Characters',
            'severity': 'Low',
            'desc': f'Found {len(special_chars)} special characters in domain. Phishers use hyphenation or symbols to bypass spam filters.'
        })
        
    # 8. Obfuscation Patterns (e.g., double slashes in paths, '@' symbol redirects)
    if '@' in domain or '@' in url.split('/')[-1]:
        risk_score += 30
        indicators.append({
            'name': 'User-Authentication Redirection Trick',
            'severity': 'High',
            'desc': 'Contains "@" symbol. Modern browsers use this to authenticate user details, redirecting the actual destination domain to whatever follows the "@" symbol.'
        })
        
    # Scale risk score
    risk_score = min(100, risk_score)
    
    # Classify Threat Level
    if risk_score < 30:
        threat_level = 'Safe'
        verdict = 'Safe'
        explanation = 'The URL structure exhibits standard patterns and connection policies. No major risk indicators were identified.'
    elif risk_score < 65:
        threat_level = 'Medium Risk'
        verdict = 'Suspicious'
        explanation = 'The URL structure has suspicious characteristics (e.g. unencrypted protocol or custom redirects). Exercise caution before entering credentials.'
    else:
        threat_level = 'Critical Risk'
        verdict = 'Phishing'
        explanation = 'The URL exhibits high-severity structural indicators characteristic of Phishing sites, such as IP hosting, brand spoofing, or obfuscation protocols.'
        
    # Model confidence level simulator for URL
    confidence = int(90 - (10 if risk_score in [40, 50, 60] else 0) + (risk_score * 0.1))
    confidence = min(99, max(75, confidence))
    
    return {
        'url': url,
        'risk_score': risk_score,
        'threat_level': threat_level,
        'verdict': verdict,
        'confidence': confidence,
        'indicators': indicators,
        'explanation': explanation
    }
