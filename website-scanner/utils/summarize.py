import openai
import pandas as pd
import os 

openai.api_key = os.getenv("OPENAI_API_KEY")

def summarize_vulnerabilities(df: pd.DataFrame) -> pd.DataFrame:
    print('summary...')
    """
    For each row in the DataFrame, this function creates a prompt for ChatGPT to summarize
    the website vulnerabilities and CCPA analysis into a short sentence (under 20 words).
    The summary is saved in a new column called 'LLM_summary'.
    """
    summaries = []
    for index, row in df.iterrows():
        # Construct the prompt for summarization
        prompt = (
            # f"I will provide you with cybersecurity vulnerabilities and feedback on CCPA compliance for a website."
            # f"If there are no vulnerabilities, ignore and o"
            # f"Summarize the following vulnerabilities and CCPA analysis in a short sentence (under 20 words). If CCPA COMPLIANT then ignore:\n\n"
            f"Website Vulnerabilities: {row['website_vulnerabilities']}\n"
            f"CCPA Analysis: {row['CCPA_analysis']}"
            f"Please provide your summary now."
        )
        try:
            response = openai.chat.completions.create(
                model="gpt-4o-mini",  # Adjust the model as necessary
                messages=[
                    {"role": "system", "content": """You are a helpful assistant. Generate a concise, natural-sounding sentence that summarizes the provided web vulnerabilities and CCPA compliance information, following the rules below:
1. If the privacy policy is not found/provided, mention site vulnerabilities but DO NOT mention CCPA compliance.
2. Keep the tone friendly, polite, and consice (under 20 words). 
4. Format your entire answer to ensure it fills in the blank for the following sentence (the blank you'll fill is XXX) : I was conducting a routine ascan using my vulnerability assessment tool and noticed a few potential security gaps on your website website_url : XXX.
5. Format your answer to start with : Your website ...
"""},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.5,
                max_tokens=60  # This ensures a short response
            )
            summary_text = response.choices[0].message.content.strip()
        except Exception as e:
            summary_text = f"Error: {e}"
        summaries.append(summary_text)
    
    df['LLM_summary'] = summaries
    return df

def summarize_consequences(df: pd.DataFrame) -> pd.DataFrame:
    print('consequences...')
    """
    For each row in the DataFrame, this function creates a prompt for ChatGPT to summarize
    the consequences of not addressing the vulnerabilities in a short sentence (under 20 words).
    The consequence summary is saved in a new column called 'LLM_consequences'.
    """
    consequences = []
    for index, row in df.iterrows():
        prompt = (
            f"Based on the following website vulnerabilities and CCPA analysis, "
            f"explain the consequences of not addressing these vulnerabilities and CCPA noncompliance (if not compliant) in a short sentence (under 20 words):\n\n"
            f"Website Vulnerabilities: {row['website_vulnerabilities']}\n"
            f"CCPA Analysis: {row['CCPA_analysis']}"
        )
        try:
            response = openai.chat.completions.create(
                model="gpt-4o-mini",  # Adjust the model as necessary
                messages=[
                    {"role": "system", "content": """You are a helpful assistant. Generate a concise, natural-sounding sentence that summarizes the consequences of ignoring web vulnerabilities and CCPA noncompliance, following the rules below:
1. If the the privacy policy is not found/provided, **only** mention the missing privacy policy (do not mention general CCPA compliance).
2. If the CCPA feedback is compliant, ignore CCPA and privacy policy consequences altogether.
3. Make a summary of the potential negative consequences that could occur if one ignores the web vulnerabilities provided and/or CCPA noncompliance (if applicable).
4. Keep the tone friendly, polite, and consice (under 20 words). 
5. Format your entire answer to ensure it fills in the blank for the following sentence (the blank you'll fill is XXX) : I was conducting a routine ascan using my vulnerability assessment tool and noticed a few potential security gaps on your website website_url : [list of vulnerabilities]. Failure to address these issues could lead to XXX.
"""},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.5,
                max_tokens=60
            )
            consequence_text = response.choices[0].message.content.strip()
        except Exception as e:
            consequence_text = f"Error: {e}"
        consequences.append(consequence_text)
    
    df['LLM_consequences'] = consequences
    return df
