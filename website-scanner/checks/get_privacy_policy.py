import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def get_privacy_policy(url, timeout=10):
    """
    Given a URL, try to locate and fetch its privacy policy text.
    Follows redirects and returns the policy text if found;
    otherwise returns 'No Privacy Policy Found'.
    """
    try:
        # 1) Fetch the homepage, following redirects
        response = requests.get(url, timeout=timeout, allow_redirects=True)
        if response.status_code != 200:
            return "No Privacy Policy Found"
        
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
            return "No Privacy Policy Found"
        
        # 4) Follow the first 'privacy' link (heuristic)
        privacy_link = candidate_links[0]
        full_privacy_url = urljoin(final_url, privacy_link)  # handle relative URLs
        print('full_privacy_url = ', full_privacy_url)
        # 5) Fetch the privacy policy page (again following redirects)
        privacy_response = requests.get(full_privacy_url, timeout=timeout, allow_redirects=True)
        if privacy_response.status_code != 200:
            return "No Privacy Policy Found"
        
        # 6) Extract text
        privacy_soup = BeautifulSoup(privacy_response.text, 'html.parser')
        policy_text = privacy_soup.get_text(separator=' ', strip=True)
        
        if policy_text:
            return policy_text
        else:
            return "No Privacy Policy Found"
    
    except Exception:
        # Log or handle specific exceptions as needed
        return "No Privacy Policy Found"




if __name__ == "__main__":
    # website = 'http://www.plexicus.com'
    # website = 'https://www.gotlanded.com'
    # website = 'https://www.jibb.ai/'
    # website = 'https://www.astroinfosec.com'
    # website = 'https://www.withfeeling.ai/'
    website = 'https://tqdlaw.com'
    # www.plexicus.com
    # driver = get_privacy_policy()
    privacy_policy = get_privacy_policy(website)
    print('PRIVACY POLICY = :', privacy_policy)
    # print('ANALYSIS = ', ccpa_analysis(privacy_policy))

