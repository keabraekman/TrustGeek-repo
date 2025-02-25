import re
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import os
import openai
import pandas as pd

import undetected_chromedriver as uc

from seleniumbase import Driver
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities


from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.service import Service


import time
import re
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC


import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin


# DEEPSEEK INTEGRATION
from openai import OpenAI
deepseek_api_key = os.getenv("DEEPSEEK_API_KEY")
client = OpenAI(api_key=deepseek_api_key, base_url="https://api.deepseek.com")


def get_privacy_policy(url, timeout=10):
    """
    Given a URL, try to locate and fetch its privacy policy text.
    Follows redirects and returns the policy text if found;
    otherwise returns 'Privacy policy not found.'.
    """
    try:
        # 1) Fetch the homepage, following redirects
        response = requests.get(url, timeout=timeout, allow_redirects=True)
        if response.status_code != 200:
            return "Privacy policy not found."
        
        # The final URL after any redirection
        final_url = response.url
        
        # 2) Parse HTML
        soup = BeautifulSoup(response.text, 'html.parser')
        print('soup = ', soup)
        
        # 3) Find links that might point to a privacy policy
        candidate_links = []
        for link in soup.find_all('a', href=True):
            text_lower = (link.get_text() or "").strip().lower()
            href_lower = link['href'].lower()
            print('href_lower = ', href_lower)
            if "privacy" in text_lower or "privacy" in href_lower:
                candidate_links.append(link['href'])
        print('candidate_links = ', candidate_links)
        if not candidate_links:
            return "Privacy policy not found."
        
        # 4) Follow the first 'privacy' link (heuristic)
        privacy_link = candidate_links[0]
        full_privacy_url = urljoin(final_url, privacy_link)  # handle relative URLs
        print('full_privacy_url = ', full_privacy_url)
        # 5) Fetch the privacy policy page (again following redirects)
        privacy_response = requests.get(full_privacy_url, timeout=timeout, allow_redirects=True)
        if privacy_response.status_code != 200:
            return "Privacy policy not found."
        
        # 6) Extract text
        privacy_soup = BeautifulSoup(privacy_response.text, 'html.parser')
        policy_text = privacy_soup.get_text(separator=' ', strip=True)
        
        if policy_text:
            return policy_text
        else:
            return "Privacy policy not found."
    
    except Exception:
        # Log or handle specific exceptions as needed
        return "Privacy policy not found."



chrome_options = uc.ChromeOptions()
chrome_options.add_argument("--headless")  
chrome_options.add_argument("--disable-gpu")
chrome_options.add_argument("--no-sandbox")
chrome_options.add_argument("--disable-extensions")


openai.api_key = os.getenv("OPENAI_API_KEY")



def ccpa_analysis(privacy_policy):
    print('ccpa_analysis!!!!!')
    print('analyzing : ', privacy_policy[:50])
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
        # response = client.chat.completions.create(
            model="gpt-4o-mini",  # Use the appropriate model name, e.g., "gpt-4" or "gpt-3.5-turbo"
            # model = "deepseek-chat",
            messages=[
                {"role": "system", "content": "You are a privacy policy compliance analyzer."},
                {"role": "user", "content": prompt}
            ],
            # stream=False,
            temperature=0,
            max_tokens=150  # Adjust token limit as needed.
        )
        answer = response.choices[0].message.content.strip()
        print('CCPA ANALYSIS = ', answer)
        return answer
    
    except Exception as e:
        print("Error in CCPA analysis: {e}")
        return f"Error in CCPA analysis: {e}"



def ccpa_analysis_output(df):
    """Processes the DataFrame by checking CCPA compliance for each website's privacy policy.
    A new driver is created every 30 iterations to help avoid resource issues.
    """
    results = []
    total = len(df)
    try:
        for i, website in enumerate(df['Company Website Full']):
        # for i, website in enumerate(df['Company Website Full'][:20]):
            if pd.notnull(website):
                analysis = ccpa_analysis(get_privacy_policy('https://' + website))
            else:
                analysis = "No URL provided"
            results.append(analysis)
            progress = ((i + 1) / total) * 100
            print(f"Progress: {progress:.2f}%")
    except Exception as e:
        print(f"An error occurred: {e}")
    df['CCPA_analysis'] = results
    # df.loc[df.index[:max_rows], 'CCPA_analysis'] = results
    return df





if __name__ == "__main__":
    # website = 'http://www.plexicus.com'
    website = 'https://www.gotlanded.com'
    # www.plexicus.com
    privacy_policy = get_privacy_policy(website)
    print('PRIVACY POLICY = :', privacy_policy)
    print('ANALYSIS = ', ccpa_analysis(privacy_policy))

