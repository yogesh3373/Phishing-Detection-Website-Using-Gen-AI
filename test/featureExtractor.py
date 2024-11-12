import whois
from urllib.parse import urlparse
import httpx
import pickle as pk
import pandas as pd
import extractorFunctions as ef
from typing import List
import os

#Function to extract features
def featureExtraction(url: str) -> pd.DataFrame:
    """
    Extract features from a given URL for phishing detection.

    Args:
        url (str): The URL to analyze.

    Returns:
        pd.DataFrame: A DataFrame containing extracted features.
    """
    features: List[float] = []
    
    # Address bar based features (6)
    features.extend([
        ef.getLength(url),
        ef.getDepth(url),
        ef.tinyURL(url),
        ef.prefixSuffix(url),
        ef.no_of_dots(url),
        ef.sensitive_word(url)
    ])

    # Domain based features (2)
    try:
        domain_name = whois.whois(urlparse(url).netloc)
        features.append(ef.domainAge(domain_name))
        features.append(ef.domainEnd(domain_name))
    except Exception:
        features.extend([1, 1])  # Default values if domain info can't be retrieved

    # HTML & Javascript based features (4)
    dom: List[int] = []
    try:
        response = httpx.get(url, timeout=10)  # Add timeout
        response.raise_for_status()  # Raise an exception for bad responses
        dom = [
            ef.iframe(response),
            ef.mouseOver(response),
            ef.forwarding(response)
        ]
    except httpx.HTTPError:
        dom = [0, 0, 0]  # Default values if request fails

    features.append(ef.has_unicode(url) + ef.haveAtSign(url) + ef.havingIP(url))

    # Load PCA model
    model_path = os.path.join('model', 'pca_model.pkl')
    try:
        with open(model_path, 'rb') as file:
            pca = pk.load(file)
    except FileNotFoundError:
        raise FileNotFoundError(f"PCA model file not found at {model_path}")

    # Apply PCA transformation
    dom_pd = pd.DataFrame([dom], columns=['iFrame', 'Web_Forwards', 'Mouse_Over'])
    features.append(pca.transform(dom_pd)[0][0])

    # Create DataFrame
    feature_names = [
        'URL_Length', 'URL_Depth', 'TinyURL', 'Prefix/Suffix', 'No_Of_Dots', 'Sensitive_Words',
        'Domain_Age', 'Domain_End', 'Have_Symbol', 'domain_att'
    ]
    return pd.DataFrame([features], columns=feature_names)
