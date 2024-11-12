import streamlit as st
import google.generativeai as genai
from datetime import datetime
import re
from featureExtractor import featureExtraction
from pycaret.classification import load_model, predict_model
from urllib.parse import urlparse

# Configure page
st.set_page_config(
    page_title="Advanced URL Security Analyzer",
    page_icon="🔒",
    layout="wide"
)

# Predefined API key - Replace with your actual key
GEMINI_API_KEY = "AIzaSyC2WZ2Qyr2w1xWBdfKQQDmZc7w8VMImwZg"

# Configure Gemini
genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel('gemini-pro')

# Load phishing detection model
phishing_model = load_model('model/phishingdetection')

# Initialize session state
if 'chat_history' not in st.session_state:
    st.session_state.chat_history = []

def is_valid_url(text):
    """Basic URL validation"""
    url_pattern = re.compile(
        r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    )
    return bool(url_pattern.search(text))

def predict_phishing(url):
    """Predict if a URL is phishing using the custom model"""
    data = featureExtraction(url)
    result = predict_model(phishing_model, data=data)
    prediction_score = result['prediction_score'][0]
    prediction_label = result['prediction_label'][0]
    
    return {
        'prediction_label': prediction_label,
        'prediction_score': prediction_score * 100,
    }

def get_combined_analysis(url):
    """Combine Gemini analysis with phishing prediction"""
    
    # Get phishing prediction
    phishing_result = predict_phishing(url)
    
    # Prepare feature data for Gemini
    features = featureExtraction(url)
    feature_str = "\n".join([f"{col}: {val}" for col, val in features.iloc[0].items()])
    
    # Gemini Analysis
    security_prompt = f"""Analyze the following URL and its extracted features for potential phishing indicators and security risks:
URL: {url}

Extracted Features:
{feature_str}

Phishing Detection Result:
Prediction: {phishing_result['prediction_label']}
Confidence: {phishing_result['prediction_score']:.2f}%

Provide a detailed security analysis following this exact structure:

1. DOMAIN ANALYSIS
- Base domain name examination
- Suspicious patterns or misspellings
- Domain age and reputation indicators
- TLD (Top Level Domain) assessment

2. URL STRUCTURE ANALYSIS
- Length and complexity
- Presence of suspicious characters
- Use of IP addresses vs domain names
- Subdomain analysis
- Path and query parameter inspection

3. SECURITY INDICATORS
- Protocol used (HTTP/HTTPS)
- Presence of security certificates
- Redirect patterns
- Use of URL shorteners

4. RISK ASSESSMENT
Risk Level: [High/Medium/Low]
Confidence: [Percentage]

5. VERDICT
[SUSPICIOUS/LEGITIMATE/HIGHLY SUSPICIOUS]

6. RECOMMENDATIONS
- Specific security advice regarding this URL
- Recommended user actions"""

    try:
        # Get Gemini analysis
        gemini_response = model.generate_content(security_prompt).text
        
        # Extract risk level and verdict from Gemini response
        risk_level_match = re.search(r'Risk Level: (High|Medium|Low)', gemini_response)
        risk_level = risk_level_match.group(1) if risk_level_match else "Unknown"
        
        verdict_match = re.search(r'5\. VERDICT\s*(SUSPICIOUS|LEGITIMATE|HIGHLY SUSPICIOUS)', gemini_response)
        verdict = verdict_match.group(1) if verdict_match else "Unknown"
        
        # Determine one-word status based on phishing prediction, risk level, and verdict
        if phishing_result['prediction_label'] == 1:
            one_word_status = "SUSPICIOUS"
        elif risk_level == "High" or verdict in ["SUSPICIOUS", "HIGHLY SUSPICIOUS"]:
            one_word_status = "SUSPICIOUS"
        else:
            one_word_status = "LEGITIMATE"
        
        combined_response = f"""
**Status: {one_word_status}**

{gemini_response}

---
Phishing Detection Model Results:
- Prediction: {"Phishing" if phishing_result['prediction_label'] == 1 else "Legitimate"}
- Confidence: {phishing_result['prediction_score']:.2f}%
"""
        return combined_response
    
    except Exception as e:
        return f"Error during analysis: {str(e)}"

# Sidebar
with st.sidebar:
    st.title("🔒 Advanced URL Analyzer")
    st.markdown("""
    ### Analysis Sources:
    1. AI-Powered Analysis (Google Gemini)
    2. Custom Phishing Detection Model
    
    ### Features:
    - Deep URL Structure Analysis
    - Real-time Threat Detection
    - Multiple Security Vendor Results
    - Comprehensive Risk Assessment
    """)
    
    if st.button("Clear History"):
        st.session_state.chat_history = []
        st.rerun()

# Main interface
st.title("🔒 Advanced URL Security Analyzer")

# Chat container
chat_container = st.container()

# Display chat history
with chat_container:
    for is_user, message in st.session_state.chat_history:
        if is_user:
            st.markdown(f"🔍 **URL Submitted**: {message}")
        else:
            # Extract the status from the message
            status_match = re.search(r'\*\*Status: (\w+)\*\*', message)
            if status_match:
                status = status_match.group(1)
                st.markdown(f"### Status: {status}")
                if status == "SUSPICIOUS":
                    st.error("⚠️ This URL is suspicious and potentially a phishing attempt!")
                else:
                    st.success("✅ This URL appears to be legitimate.")
            
            st.markdown(f"🤖 **Security Analysis**:\n{message}")
            st.markdown("---")

# User input
user_input = st.text_input("Paste a URL to analyze (must start with http:// or https://):", key="user_input")

# Handle user input
if st.button("Analyze URL") and user_input:
    if not is_valid_url(user_input):
        st.error("Please enter a valid URL starting with http:// or https://")
    else:
        with st.spinner("Analyzing URL..."):
            # Add user input to history
            st.session_state.chat_history.append((True, user_input))
            
            # Get combined analysis
            analysis_result = get_combined_analysis(user_input)
            
            # Add analysis to history
            st.session_state.chat_history.append((False, analysis_result))
            
            # Update display
            st.rerun()

# Footer
st.markdown("---")
st.markdown("💡 **Note**: This tool combines AI analysis with real-world threat intelligence for comprehensive security assessment.")
