import openai
import pandas as pd
import os 
from openai import OpenAI


openai.api_key = os.getenv("OPENAI_API_KEY")

# DEEPSEEK INTEGRATION
deepseek_api_key = os.getenv("DEEPSEEK_API_KEY")
client = OpenAI(api_key=deepseek_api_key, base_url="https://api.deepseek.com")

# DEPRECATED
# def summarize_vulnerabilities(df: pd.DataFrame) -> pd.DataFrame:
#     print('summary...')
#     """
#     For each row in the DataFrame, this function creates a prompt for ChatGPT to summarize
#     the website vulnerabilities and CCPA analysis into a short sentence (under 20 words).
#     The summary is saved in a new column called 'LLM_summary'.
#     """
#     summaries = []
#     for index, row in df.iterrows():
#         # Construct the prompt for summarization
#         prompt = (
#             # f"I will provide you with cybersecurity vulnerabilities and feedback on CCPA compliance for a website."
#             # f"If there are no vulnerabilities, ignore and o"
#             # f"Summarize the following vulnerabilities and CCPA analysis in a short sentence (under 20 words). If CCPA COMPLIANT then ignore:\n\n"
#             f"Website Vulnerabilities: {row['website_vulnerabilities']}\n"
#             f"CCPA Analysis: {row['CCPA_analysis']}"
#             f"Please provide your summary now."
#         )
#         try:
#             response = openai.chat.completions.create(
#                 model="gpt-4o-mini",  # Adjust the model as necessary
#                 messages=[
#                     {"role": "system", "content": """You are a helpful assistant. Generate a concise, natural-sounding sentence that summarizes the provided web vulnerabilities and CCPA compliance information, following the rules below:
# 1. If the privacy policy is not found/provided, mention site vulnerabilities but DO NOT mention CCPA compliance.
# 2. Keep the tone friendly, polite, and consice (under 20 words). 
# 4. Format your entire answer to ensure it fills in the blank for the following sentence (the blank you'll fill is XXX) : I was conducting a routine ascan using my vulnerability assessment tool and noticed a few potential security gaps on your website website_url : XXX.
# 5. Format your answer to start with : Your website ...
# """},
#                     {"role": "user", "content": prompt}
#                 ],
#                 temperature=0.5,
#                 max_tokens=60  # This ensures a short response
#             )
#             summary_text = response.choices[0].message.content.strip()
#         except Exception as e:
#             summary_text = f"Error: {e}"
#         summaries.append(summary_text)
    
#     df['LLM_summary'] = summaries
#     return df
# DEPRECATED
# def summarize_consequences(df: pd.DataFrame) -> pd.DataFrame:
#     print('consequences...')
#     """
#     For each row in the DataFrame, this function creates a prompt for ChatGPT to summarize
#     the consequences of not addressing the vulnerabilities in a short sentence (under 20 words).
#     The consequence summary is saved in a new column called 'LLM_consequences'.
#     """
#     consequences = []
#     for index, row in df.iterrows():
#         prompt = (
#             f"Based on the following website vulnerabilities and CCPA analysis, "
#             f"explain the consequences of not addressing these vulnerabilities and CCPA noncompliance (if not compliant) in a short sentence (under 20 words):\n\n"
#             f"Website Vulnerabilities: {row['website_vulnerabilities']}\n"
#             f"CCPA Analysis: {row['CCPA_analysis']}"
#         )
#         try:
#             response = openai.chat.completions.create(
#                 model="gpt-4o-mini",  # Adjust the model as necessary
#                 messages=[
#                     {"role": "system", "content": """You are a helpful assistant. Generate a concise, natural-sounding sentence that summarizes the consequences of ignoring web vulnerabilities and CCPA noncompliance, following the rules below:
# 1. If the the privacy policy is not found/provided, **only** mention the missing privacy policy (do not mention general CCPA compliance).
# 2. If the CCPA feedback is compliant, ignore CCPA and privacy policy consequences altogether.
# 3. Make a summary of the potential negative consequences that could occur if one ignores the web vulnerabilities provided and/or CCPA noncompliance (if applicable).
# 4. Keep the tone friendly, polite, and consice (under 20 words). 
# 5. Format your entire answer to ensure it fills in the blank for the following sentence (the blank you'll fill is XXX) : I was conducting a routine ascan using my vulnerability assessment tool and noticed a few potential security gaps on your website website_url : [list of vulnerabilities]. Failure to address these issues could lead to XXX.
# """},
#                     {"role": "user", "content": prompt}
#                 ],
#                 temperature=0.5,
#                 max_tokens=60
#             )
#             consequence_text = response.choices[0].message.content.strip()
#         except Exception as e:
#             consequence_text = f"Error: {e}"
#         consequences.append(consequence_text)
    
#     df['LLM_consequences'] = consequences
#     return df


spam_words = ("Legal", "regarding", "Access", "Access now", "Act", "Act immediately", "Act now", "Act now!", "Action", "Action required",
    "Apply here", "Apply now", "Apply now!", "Apply online", "Become a member", "Before it's too late",
    "Being a member", "Buy", "Buy direct", "Buy now", "Buy today", "Call", "Call free", "Call free/now",
    "Call me", "Call now", "Call now!", "Can we have a minute of your time?", "Cancel now",
    "Cancellation required", "Claim now", "Click", "Click below", "Click here", "Click me to download",
    "Click now", "Click this link", "Click to get", "Click to remove", "Contact us immediately",
    "Deal ending soon", "Do it now", "Do it today", "Don't delete", "Don't hesitate", "Don't waste time",
    "Don’t delete", "Exclusive deal", "Expire", "Expires today", "Final call", "For instant access",
    "For Only", "For you", "Friday before [holiday]", "Get it away", "Get it now", "Get now", "Get paid",
    "Get started", "Get started now", "Great offer", "Hurry up", "Immediately", "Info you requested",
    "Information you requested", "Instant", "Limited time", "New customers only", "Now", "Now only",
    "Offer expires", "Once in lifetime", "Only", "Order now", "Order today", "Please read",
    "Purchase now", "Sign up free", "Sign up free today", "Supplies are limited", "Take action",
    "Take action now", "This won’t last", "Time limited", "Today", "Top urgent", "Trial", "Urgent",
    "What are you waiting for?", "While supplies last", "You are a winner", "0 down", "All",
    "All natural", "All natural/new", "All new", "All-natural", "All-new", "Allowance", "As seen on",
    "As seen on Oprah", "At no cost", "Auto email removal", "Avoid bankruptcy", "Avoid",
    "Beneficial offer", "Beneficiary", "Bill 1618", "Brand new pager", "Bulk email",
    "Buying judgements", "Buying judgments", "Cable converter", "Calling creditors", "Can you help us?",
    "Cancel at any time", "Cannot be combined", "Celebrity", "Cell phone cancer scam", "Certified",
    "Chance", "Cheap", "Cheap meds", "Cialis", "Claims", "Claims not to be selling anything",
    "Claims to be in accordance with some spam law", "Claims to be legal", "Clearance", "Collect",
    "Collect child support", "Compare", "Compare now", "Compare online", "Compare rates",
    "Compete for your business", "Confidentiality", "Congratulations", "Consolidate debt and credit",
    "Consolidate your debt", "Copy accurately", "Copy DVDs", "COVID", "Cures", "Cures baldness",
    "Diagnostic", "DIAGNOSTICS", "Diet", "Dig up dirt on friends", "Direct email", "Direct marketing",
    "Eliminate debt", "Explode your business", "Fast viagra delivery", "Finance", "Financial",
    "Financial advice", "Financial independence", "Financially independent", "For new customers only",
    "Foreclosure", "Free", "Free access/money/gift", "Free bonus", "Free cell phone", "Free DVD",
    "Free grant money", "Free information", "Free installation", "Free Instant", "Free iPhone",
    "Free laptop", "Free leads", "Free Macbook", "Free offer", "Free priority mail", "Free sample",
    "Free website", "Free!", "Get", "Gift card", "Gift certificate", "Gift included", "Give it away",
    "Giving away", "Giving it away", "Gold", "Great", "Great deal", "Greetings of the day",
    "Growth hormone", "Guarantee", "Guaranteed deposit", "Guaranteed income", "Guaranteed payment",
    "Have you been turned down?", "Hello (with no name included)", "Hidden charges", "Hidden costs",
    "Hidden fees", "High score", "Home based business", "Home mortgage", "Human", "Human growth hormone",
    "If only it were that easy", "Important information", "Important notification", "Instant weight loss",
    "Insurance Lose weight", "Internet marketing", "Investment decision", "Invoice", "It’s effective",
    "Job alert", "Junk", "Lambo", "Laser printer", "Last Day", "Legal notice", "Life",
    "Life insurance", "Lifetime access", "Lifetime deal", "Limited", "Limited amount", "Limited number",
    "Limited offer", "Limited supply", "Limited time offer", "Limited time only", "Loan",
    "Long distance phone number", "Long distance phone offer", "Lose weight", "Lose weight fast",
    "Lose weight spam", "Lottery", "Lower interest rate", "Lower interest rates", "Lower monthly payment",
    "Lower your mortgage rate", "Lowest insurance rates", "Lowest interest rate", "Lowest rate",
    "Lowest rates", "Luxury", "Luxury car", "Mail in order form", "Main in order form",
    "Mark this as not junk", "Mass email", "Medical", "Medicine", "Meet girls", "Meet me", "Meet singles",
    "Meet women", "Member", "Member stuff", "Message contains disclaimer", "Message from", "Millionaire",
    "Millions", "MLM", "Multi-level marketing", "Name", "Near you", "Never before", "New",
    "New domain extensions", "Nigerian", "No age restrictions", "No catch", "No claim forms", "No cost",
    "No credit check", "No credit experience", "No deposit required", "No disappointment", "No experience",
    "No fees", "No gimmick", "No hidden", "No hidden costs", "No hidden fees", "No hidden сosts",
    "No interest", "No interests", "No inventory", "No investment", "No investment required",
    "No medical exams", "No middleman", "No obligation", "No payment required", "No purchase necessary",
    "No questions asked", "No selling", "No strings attached", "No-obligation", "Nominated bank account",
    "Not intended", "Not junk", "Not scam", "Not spam", "Notspam", "Number 1", "Obligation", "Off",
    "Off everything", "Off shore", "Offer extended", "Offers", "Offshore", "One hundred percent",
    "One-time", "Online biz opportunity", "Online degree", "Online income", "Online job", "Open",
    "Opportunity", "Opt-in", "Order", "Order shipped by", "Order status", "Orders shipped by",
    "Orders shipped by shopper", "Outstanding value", "Outstanding values", "Password", "Passwords",
    "Pay your bills", "Per day/per week/per year", "Per month", "Perfect", "Performance", "Phone",
    "Please", "Please open", "Presently", "Print form signature", "Print from signature",
    "Print out and fax", "Priority mail", "Privately owned funds", "Prizes", "Problem with shipping",
    "Problem with your order", "Produced and sent out", "Profit", "Promise you", "Purchase", "Pure Profits",
    "Quotes", "Rate", "Real thing", "Rebate", "Reduce debt", "Refinance home", "Refinanced home",
    "Refund", "Removal instructions", "Removes", "Removes wrinkles", "Replica watches")


def summarize_and_consequences(df):
    print('Adding personalizations')
    summaries = []
    for index, row in df.iterrows():
        print('summary ', index)
        # Construct the prompt for summarization
        prompt = (
            f"I need you to write a personalized sentence to the owner of a website."
            f"I will give you a list of that website's vulnerabilities (could be None)"
            f"I will give you that website's CCPA compliance status. Three posibilities : (1. CCPA compliant, 2. CCPA noncompliant, or 3. website doesn't have a privacy policy)"
            f"Website Vulnerabilities: {row['website_vulnerabilities']}\n"
            f"CCPA Status: {row['CCPA_analysis']}"
            f"Using this information, write a short sentence explaining in simple terms :"
            f"- the website's vulnerabilities and the consequences of not addressing these vulnerabilities."
            f"- IF the website lacks a privacy policy, the risks of not having a privacy policy."
            f"- IF the website HAS a noncompliant privacy policy, the risk of not being California Consumer Protections Act Compliant, provide a very short explanation of what CCPA is."
            f"- IF the website IS CCPA compliant, DO NOT MENTION ANYTHING ABOUT CCPA Compliance"
        )
        try:
            # response = openai.chat.completions.create(
            response = client.chat.completions.create(
                # model="gpt-4o-mini",  # Adjust the model as necessary
                # model="gpt-o3-mini",
                model = "deepseek-chat",
                messages=[
                    {"role": "system", "content": """You are a helpful assistant. Always respond in exactly one sentence, keep it LIGHT and POLITE. Follow this structure:
                     You are not allowed to use any of the following words : {spam_words}
1) Mention vulnerabilities.
2) Mention consequences.
3) If no privacy policy, mention that risk.
4) If noncompliant, mention that risk."""},
                    {"role": "user", "content": prompt}
                ],
                stream=False,
                temperature=0.3,
                max_tokens=100  # This ensures a short response
            )
            summary_text = response.choices[0].message.content.strip()
        except Exception as e:
            summary_text = f"Error: {e}"
        summaries.append(summary_text)
    df['LLM_personalizations'] = summaries
    return df



def summarize_and_consequences_test(vulnerabilities, CCPA_analysis):
    prompt = (
        f"I need you to write a personalized sentence to the owner of a website."
        f"I will give you a list of that website's vulnerabilities (could be None)"
        f"I will give you that website's CCPA compliance status. Three posibilities : (1. CCPA compliant, 2. CCPA noncompliant, or 3. website doesn't have a privacy policy)"
        f"Website Vulnerabilities: {vulnerabilities}\n"
        f"CCPA Status: {CCPA_analysis}"
        f"Using this information, write a short sentence explaining in simple terms :"
        f"- the website's vulnerabilities and the consequences of not addressing these vulnerabilities."
        f"- IF the website lacks a privacy policy, the risks of not having a privacy policy."
        f"- IF the website HAS a noncompliant privacy policy, the risk of not being California Consumer Protections Act Compliant, provide a very short explanation of what CCPA is."
        f"- IF the website IS CCPA compliant, DO NOT MENTION ANYTHING ABOUT CCPA Compliance"
    )
    try:
        # response = openai.chat.completions.create(
        response = client.chat.completions.create(
            # model="gpt-4o-mini",  # Adjust the model as necessary
            # model="gpt-o3-mini",
            model = "deepseek-chat",
            messages=[
                {"role": "system", "content": """You are a helpful assistant. Always respond in exactly one sentence, keep it LIGHT and POLITE. Follow this structure:
                    You are not allowed to use any of the following words : {spam_words}
1) Mention vulnerabilities.
2) Mention consequences.
3) If no privacy policy, mention that risk.
4) If noncompliant, mention that risk."""},
                {"role": "user", "content": prompt}
            ],
            # stream=False,
            temperature=0.3,
            max_tokens=200  # This ensures a short response
        )
        summary_text = response.choices[0].message.content.strip()
    except Exception as e:
        summary_text = f"Error: {e}"
    return summary_text



if __name__ == "__main__":
    vulnerabilities = """{'header_errors': ['Content-Security-Policy header missing', 'X-Frame-Options header missing', 'Referrer-Policy header missing', 'X-XSS-Protection header missing'], 'cookie_errors': ["Cookie missing 'Secure' flag", "Cookie missing 'HttpOnly' flag"]}"""
    CCPA_analysis = 'Not compliant; it lacks clear information on consumer rights under CCPA, such as the right to opt-out of data selling.'
    print(summarize_and_consequences_test(vulnerabilities, CCPA_analysis))