"""
Module: AskAI.py
Purpose: AI-powered recommendations using Google Gemini
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.config import get_env

try:
    from google import genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False

_api_key = get_env('GEMINI_API_KEY')
_client = None

def _get_client():
    """Get or create Gemini client."""
    global _client
    
    if not GEMINI_AVAILABLE:
        return None
    
    if not _api_key:
        return None
    
    if _client is None:
        _client = genai.Client(api_key=_api_key)
    
    return _client


def send_message(cve_id: str, tech_version: str, cve_description: str, asset_name: str):
    """
    Generate AI-powered vulnerability recommendation.
    
    Args:
        cve_id: CVE identifier
        tech_version: Technology version
        cve_description: CVE description
        asset_name: Asset name
    
    Returns:
        Recommendation text or None if error
    """
    client = _get_client()
    
    if not client:
        return None
    
    prompt = f"""
    Acting as a Cyber Security Assistant.
    
    I will provide you with a TECHNICAL DESCRIPTION of a vulnerability (Source: NVD) and the USER'S CURRENT VERSION.
    Your task is to REWRITE it for a non-technical user in Indonesian and suggest fixes.

    --- SOURCE DATA ---
    Asset Name: {asset_name}
    User's Current Version: {tech_version}
    CVE ID: {cve_id}
    Raw Description: "{cve_description}"
    -------------------

    INSTRUCTIONS:
    1. **Deskripsi Singkat**: Translate the "Raw Description" into simple Indonesian. Summarize it in 1-2 sentences. Focus on the impact (what can happen like data theft or crash).
    
    2. **Rekomendasi (Personalized)**: 
       - **Step 1 is MANDATORY**: You MUST compare the user's version with a safe version. 
       - **Format for Step 1**: "Saat ini sistem menggunakan versi {tech_version}, sangat disarankan untuk segera melakukan update ke versi [INSERT SAFE/LATEST VERSION HERE] atau yang lebih baru."
       - Use your knowledge to suggest the next safe version (e.g., if user has Node 15, suggest Node 18 LTS or 20 LTS).
       - **Step 2**: Provide one additional mitigation step (e.g., check config, firewall, or monitor logs).

    STRICT OUTPUT FORMAT (Pure Text):
    Pemberitahuan, Telah terdeteksi kerentanan pada aset {asset_name} berikut adalah detailnya.
    CVE ID = {cve_id}
    Deskripsi Singkat = [Gemini writes the summary here]

    Rekomendasi langkah penanganan:
    1. [Gemini: Insert the personalized update instruction mentioning version {tech_version}]
    2. [Gemini: Insert additional mitigation step]
    """
    
    try:
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt
        )
        return response.text
    except Exception as e:
        print(f"Gemini API error: {e}")
        return None


def compare_cve_details(desc_nvd: str, desc_vulners: str):
    """
    Compare two CVE descriptions for semantic match.
    
    Args:
        desc_nvd: NVD description
        desc_vulners: Vulners description
    
    Returns:
        True if match found, False otherwise
    """
    client = _get_client()
    
    if not client:
        return False

    prompt = f"""
    Role: Senior Security Auditor.
    
    Task: Determine if there is a MATCH or INCLUSION between the two descriptions.
    
    TEXT A:
    "{desc_nvd}"

    TEXT B:
    "{desc_vulners}"

    CRITICAL EVALUATION LOGIC (Follow in order):
    1. **ID MATCH (Silver Bullet):** Scan both texts for CVE IDs (e.g., CVE-2024-7347). 
       - If BOTH texts contain the SAME CVE ID, return 'True' IMMEDIATELY. 
       - Ignore the fact that one text might list other CVEs too.
       
    2. **SUBSET MATCH:** If one text is a list/advisory (containing multiple fixes) and the other text describes ONE of those fixes, return 'True'.
       - Example: Text A describes "Bug in MP4 module". Text B says "Fixes: Bug in MP4 module, Bug in HTTP module". -> Result: True.
       
    3. **SEMANTIC MATCH:** If no CVE IDs are present, check if they describe the same software (e.g., Nginx) AND the same component/issue (e.g., ngx_http_mp4_module memory corruption).

    OUTPUT: True or False only.
    """

    try:
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt
        )
        
        if response and "true" in response.text.lower():
            return True
        return False
    except Exception as e:
        print(f"Gemini API error: {e}")
        return False


if __name__ == '__main__':
    print("Testing AskAI...")
    print(f"Gemini API Key configured: {'Yes' if _api_key else 'No'}")
    print(f"Gemini available: {'Yes' if GEMINI_AVAILABLE else 'No'}")
    
    if _api_key and GEMINI_AVAILABLE:
        print("\nTesting send_message...")
        result = send_message(
            cve_id="CVE-2023-1234",
            tech_version="nginx 1.18.0",
            cve_description="A vulnerability in nginx allows remote attackers to cause a denial of service.",
            asset_name="test-server"
        )
        if result:
            print("Response received:")
            print(result[:500])
        else:
            print("No response received")