import pandas as pd
import json
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup


def excel_to_json(excel_file, json_file):
    # Read the Excel file.
    df = pd.read_excel(excel_file)
    # Remove rows without an email.
    df = df[df["email"].notna() & (df["email"].astype(str).str.strip() != "")]
    # Drop duplicate IDs, keeping only the first occurrence.
    df = df.drop_duplicates(subset="id", keep="first")
    # Convert DataFrame to a dictionary keyed by the 'id' column.
    data = df.set_index("id").to_dict(orient="index")
    # Write the dictionary to a JSON file.
    with open(json_file, "w") as outfile:
        json.dump(data, outfile, indent=4)

def is_valid_website(url):
    """
    Return True if the URL is a string that, after stripping, is not empty,
    "nan", or "none" (case-insensitive).
    """
    if not isinstance(url, str):
        return False
    cleaned = url.strip().lower()
    return cleaned not in ("", "nan", "none")

excel_file = "../Lead-List-1.xlsx"
json_file = "leads.json"

unique_urls = [
    "/privacy-policy/",
    "legal-privacy-policy/",
    "/privacy-policy",
    "https://jam-labs.com/wp-content/uploads/2021/12/Terms_and_Conditions.pdf",
    "/legal/privacy",
    "/privacy/",
    "/terms-and-conditions/",
    "/policies/privacy-policy",
    "/privacy-statement/",
    "https://www.sweetwaterhrv.com/documentation/eula-tos-pr-capr.pdf",
    "/privacy",
    "/privacyPolicy",
    "/wpautoterms/privacy-policy/",
    "/privacy-policy-2",
    "/privacy-policy-chorology-inc/",
    "/agreements/privacypolicy/",
    "/legal/privacy-policy",
    'https://acrobat.adobe.com/id/urn:aaid:sc:AP:eaf7492e-c457-425b-8af2-18340b68da27',
    '/privacy/',
    '/privacy-policy-2/',
    'https://dosisinc.com/media/dosis-online-privacy-policy.pdf',
    '/security/privacy',
    '/privacypolicy',
    'utility-pages/privacy-policy',
    '/website/privacy-policy'
]

def fetch_privacy_policy(website_url):
    if not is_valid_website(website_url):
        print(f"Invalid website URL: {website_url}. Skipping.")
        return None
    website_url = website_url.strip()
    for candidate in unique_urls:
        if candidate.startswith("http"):
            policy_url = candidate
        else:
            policy_url = urljoin(website_url, candidate)
        try:
            print(f"Trying {policy_url} ...")
            response = requests.get(policy_url, timeout=10)
            if response.status_code == 200:
                print(f"Found privacy policy at: {policy_url}")
                content_type = response.headers.get('Content-Type', '').lower()
                if 'pdf' in content_type:
                    encoded = base64.b64encode(response.content).decode('utf-8')
                    return encoded
                elif 'html' in content_type:
                    soup = BeautifulSoup(response.text, "html.parser")
                    text = soup.get_text(separator='\n')
                    return text.strip()
                else:
                    # If not PDF or HTML, just return the text content.
                    return response.text
        except Exception as e:
            print(f"Error fetching {policy_url}: {e}")
    return None


def add_privacy_policy_to_json(input_json_file, output_json_file):
    """
    Load the JSON file, remove entries that lack a valid email or website, and for each remaining entry,
    attempt to scrape the privacy policy by appending candidate endpoints to the website URL.
    Adds a new key "privacy policy" with the content (or None if none of the endpoints worked) and writes the
    updated data to a new JSON file.
    """
    with open(input_json_file, "r") as f:
        data = json.load(f)
    
    # Filter out entries that don't have both a valid email and a valid website URL.
    filtered_data = {
        key: entry for key, entry in data.items()
        if entry.get("email") and is_valid_website(entry.get("website_url"))
    }
    
    for key, entry in filtered_data.items():
        website_url = entry.get("website_url")
        policy_content = fetch_privacy_policy(website_url)
        entry["privacy policy"] = policy_content

    with open(output_json_file, "w") as f:
        json.dump(filtered_data, f, indent=4)
    print(f"Updated JSON saved as {output_json_file}")

excel_to_json(excel_file, json_file)
print(f"Converted {excel_file} to {json_file}")
input_json = "leads.json"
output_json = "leads_with_privacy.json"
add_privacy_policy_to_json(input_json, output_json)


# policies = 0
# with open("leads_with_privacy.json", "r") as f:
#     data = json.load(f)
# for id in data:
#     if isinstance(data[id].get('privacy policy'), str):
#         policies += 1
#     # if data[id]['privacy policy'] != None:
#     #     policies += 1
# print(policies)
# for i, (key, entry) in enumerate(data.items()):
#     print(f"Entry ID: {key}")
#     print(entry)
#     print("-" * 40)