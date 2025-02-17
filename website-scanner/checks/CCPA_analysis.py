import re
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import os
import openai

openai.api_key = os.getenv("OPENAI_API_KEY")

unique_urls = [
    "/privacy-policy/",
    "legal-privacy-policy/",
    "/privacy-policy",
    "/legal/privacy",
    "/privacy/",
    "/terms-and-conditions/",
    "/policies/privacy-policy",
    "/privacy-statement/",
    "/privacy",
    "/privacyPolicy",
    "/wpautoterms/privacy-policy/",
    "/privacy-policy-2",
    "/privacy-policy-chorology-inc/",
    "/agreements/privacypolicy/",
    "/legal/privacy-policy",
    '/privacy/',
    '/privacy-policy-2/',
    '/security/privacy',
    '/privacypolicy',
    'utility-pages/privacy-policy',
    '/website/privacy-policy'
]


def extract_text(html_content):
    """Extract and clean text from HTML, removing scripts and styles."""
    soup = BeautifulSoup(html_content, 'html.parser')
    for tag in soup(['script', 'style']):
        tag.decompose()  # Remove these tags
    text = soup.get_text(separator='\n')
    return '\n'.join(line.strip() for line in text.splitlines() if line.strip())


def urls_equivalent(url1, url2):
    """Return True if the two URLs are equivalent, ignoring trailing slashes."""
    return url1.rstrip('/') == url2.rstrip('/')


def is_error_page(text):
    """Check if the text indicates an error page (e.g., 404 or 'not found')."""
    # Customize this list of error indicators as needed.
    error_indicators = [
        '404', 'not found', 'page not found', 'error'
    ]
    for indicator in error_indicators:
        if re.search(indicator, text, re.IGNORECASE):
            return True
    return False


def get_privacy_policy(url):
    """Uses headless Selenium to retrieve a website's privacy policy.
    
    Returns the extracted text if a distinct privacy policy page is found,
    otherwise returns "Privacy policy not found."
    """
    chrome_options = Options()
    chrome_options.add_argument("--headless")    # Run headless
    chrome_options.add_argument("--disable-gpu") # Disable GPU
    chrome_options.add_argument("--no-sandbox")  # Bypass OS security model

    driver = webdriver.Chrome(options=chrome_options)
    driver.implicitly_wait(10)
    
    try:
        # Step 1: Load homepage and search for a privacy policy link.
        driver.get(url)
        homepage_url = driver.current_url  # May include redirects
        homepage_html = driver.page_source
        soup = BeautifulSoup(homepage_html, 'html.parser')
        policy_link = None

        # Look through all <a> tags for a candidate link containing 'privacy'.
        for a in soup.find_all('a', href=True):
            if re.search(r'privacy', a.get_text(), re.IGNORECASE):
                candidate_url = urljoin(url, a['href'])
                if not urls_equivalent(candidate_url, homepage_url):
                    policy_link = candidate_url
                    break  # Use the first valid candidate

        if policy_link:
            driver.get(policy_link)
            if urls_equivalent(driver.current_url, homepage_url):
                policy_link = None  # Not a distinct page.
            else:
                html_policy = driver.page_source
                extracted = extract_text(html_policy)
                if extracted and not is_error_page(extracted):
                    return extracted

        # Step 2: Fallback by trying common URL paths.
        for path in unique_urls:
            privacy_url = urljoin(url, path)
            if urls_equivalent(privacy_url, homepage_url):
                continue
            driver.get(privacy_url)
            if urls_equivalent(driver.current_url, homepage_url):
                continue
            html_policy = driver.page_source
            if "please enable javascript" in html_policy.lower():
                continue
            extracted = extract_text(html_policy)
            if extracted and not is_error_page(extracted):
                return extracted

        return "Privacy policy not found."

    except Exception as e:
        # return f"Error: {e}"
        return "Privacy policy not found."

    finally:
        driver.quit()




def ccpa_analysis(privacy_policy):
    """
    Analyzes the provided privacy_policy text for CCPA compliance.
    
    If no privacy policy was found (i.e., privacy_policy == "Privacy policy not found." or similar),
    returns "No privacy policy found on the website".
    
    Otherwise, it invokes ChatGPT to determine if the policy is CCPA compliant.
    - If compliant, ChatGPT should return "CCPA COMPLIANT".
    - If not compliant, ChatGPT returns a brief summary (50 words or less) explaining why.
    """
    # Check if no privacy policy was found.
    if privacy_policy == 'Privacy policy not found.':
        return "No privacy policy found on the website."
    
    # Prepare the prompt for ChatGPT.
    prompt = (
        "Analyze the following privacy policy text and determine if it is CCPA compliant. "
        "If it is compliant, simply return 'CCPA COMPLIANT'. Otherwise, in 20 words or less, "
        "provide a very basic summary explaining why it is not compliant.\n\n"
        f"Privacy Policy:\n{privacy_policy}"
    )
    
    try:
        # Call the OpenAI ChatCompletion API using the new interface.
        response = openai.chat.completions.create(
            model="gpt-4o-mini",  # Use the appropriate model name, e.g., "gpt-4" or "gpt-3.5-turbo"
            messages=[
                {"role": "system", "content": "You are a privacy policy compliance analyzer."},
                {"role": "user", "content": prompt}
            ],
            temperature=0,
            max_tokens=150  # Adjust token limit as needed.
        )
        answer = response.choices[0].message.content.strip()
        return answer
    
    except Exception as e:
        return f"Error in CCPA analysis: {e}"


if __name__ == "__main__":
    website = 'http://www.plexicus.com'
    # www.plexicus.com
    privacy_policy = get_privacy_policy(website)
    print('PRIVACYT POLICY = :', privacy_policy)
    print('ANALYSIS = ', ccpa_analysis(privacy_policy))
