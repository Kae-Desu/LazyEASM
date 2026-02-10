from google import genai

client = genai.Client(api_key="GEMINIKEY")

def send_message(cve_id, tech_version, cve_description, nama_aset):
    prompt = f"""
    Acting as a Cyber Security Assistant.
    
    I will provide you with a TECHNICAL DESCRIPTION of a vulnerability (Source: NVD) and the USER'S CURRENT VERSION.
    Your task is to REWRITE it for a non-technical user in Indonesian and suggest fixes.

    --- SOURCE DATA ---
    Asset Name: {nama_aset}
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
    Pemberitahuan, Telah terdeteksi kerentanan pada aset {nama_aset} berikut adalah detailnya.
    CVE ID = {cve_id}
    Deskripsi Singkat = [Gemini writes the summary here]

    Rekomendasi langkah penanganan:
    1. [Gemini: Insert the personalized update instruction mentioning version {tech_version}]
    2. [Gemini: Insert additional mitigation step]
    """
    
    try:
        response = client.models.generate_content(
            model="gemini-2.5-flash-preview-09-2025",
            contents=prompt
        )
        return response.text
    except Exception as e:
        print(f"An error occurred: {e}")

def compare_cve_details(desc_nvd, desc_vulners):
    # generation_config = genai.types.GenerateContentConfig(
    #     temperature=0.2,
    #     top_p=1,
    #     max_output_tokens=10,
    # )

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
            model="gemini-2.5-flash-preview-09-2025",
            contents=prompt
        )
        
        if "true" in response:
            return True
        return False
    except Exception as e:
        print(f"Error Gemini: {e}")
        return False # Fail-safe