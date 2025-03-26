# This python script will be used to filter OUT all the websites and leads that are CCPA compliant.
# The email strategy is showing weaknesses and limitations. So if we go towards a more phonecall approach
# We need to filter out all the companies that are CCPA compliant.

import pandas as pd

def remove_ccpa_compliant_and_missing_phone(input_csv, output_csv):
    """
    Reads a CSV file, removes rows where 'CCPA_analysis' is 'CCPA COMPLIANT' and rows
    that do not have a company phone number (assuming column 'company_phone'),
    then writes the result to a new CSV file.
    
    Parameters:
        input_csv (str): Path to the input CSV file.
        output_csv (str): Path where the filtered CSV will be saved.
        
    Returns:
        pd.DataFrame: The filtered DataFrame.
    """
    # Read the CSV into a DataFrame
    df = pd.read_csv(input_csv)
    
    # Filter out rows where CCPA_analysis equals "CCPA COMPLIANT"
    df = df[df['CCPA_analysis'] != "CCPA COMPLIANT"]
    
    # Remove rows where the company phone number is missing or empty.
    # Update 'company_phone' to match the actual column name in your CSV if needed.
    df = df[df['Company Phone Number'].notnull() & (df['Company Phone Number'].astype(str).str.strip() != "")]
    
    # Write the filtered DataFrame to a new CSV file
    df.to_csv(output_csv, index=False)
    
    return df

# Example usage:
if __name__ == "__main__":
    input_csv_path = "../data/lead-list2-processed.csv"  # Update this path if needed
    output_csv_path = "../data/lead-list2-ccpa-noncompliants-with-phone.csv"
    
    # Remove rows that are CCPA compliant and those missing a phone number
    filtered_data = remove_ccpa_compliant_and_missing_phone(input_csv_path, output_csv_path)
    print(f"Filtered CSV saved to: {output_csv_path}")