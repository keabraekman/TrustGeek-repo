from utils.data_cleaning import clean_spreadsheet
from checks.https_check import *
import pandas as pd

def main():
    input_file = 'data/lead-list1.csv'
    output_file = 'data/lead-list1-processed.csv'
    df = pd.read_csv(input_file)
    # Removes all the leads without a website and email
    df_clean = clean_spreadsheet(df)
    df_clean2 = https_diagnostic_output(df_clean)
    # Checks if the website uses https
    df_clean2.to_csv(output_file, index=False)
    print(f"Cleaned CSV file saved to {output_file}")

if __name__ == "__main__":
    main()