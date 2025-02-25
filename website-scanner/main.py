from utils.data_cleaning import *
from checks.https_check import *
from checks.security_check import *
import pandas as pd
from checks.CCPA_analysis import *
from utils.summarize import *
from checks.get_privacy_policy import get_privacy_policy

def main():
    input_file = 'data/lead-list2.csv'
    output_file = 'data/lead-list2-processed.csv'
    df = pd.read_csv(input_file)
    # Removes all the leads without a website and email
    
    df_clean = clean_spreadsheet(df)
    df_clean2 = website_vulnerabilities_output(df_clean)
    df_clean3 = ccpa_analysis_output(df_clean2)
    
    # df_clean3.to_csv(output_file, index=False)
    # input_file = 'data/lead-list1-processed2.csv'
    # output_file = 'data/lead-list1-processed3.csv'
    # df = pd.read_csv(input_file)
    # print('removing the compliant websites')
    df_clean4 = remove_compliants(df_clean3)

    # print('adding personalization')
    df_clean5 = summarize_and_consequences(df_clean4)
    df_clean5.to_csv(output_file, index=False)
    print(f"Cleaned CSV file saved to {output_file}")

if __name__ == "__main__":
    main()