from utils.data_cleaning import clean_spreadsheet
import pandas as pd

def main():
    input_file = 'data/lead-list1.csv'
    output_file = 'data/lead-list1-processed.csv'
    df = pd.read_csv(input_file)
    # Removes all the leads without a website and email
    df_clean = clean_spreadsheet(df)
    # Checks if the website uses https

    
    df_clean.to_csv(output_file, index=False)
    print(f"Cleaned CSV file saved to {output_file}")

if __name__ == "__main__":
    main()