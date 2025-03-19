# This python script will be used to filter OUT all the websites and leads that are CCPA compliant.
# The email strategy is showing weaknesses and limitations. So if we go towards a more phonecall approach
# We need to filter out all the companies that are CCPA compliant.

import pandas as pd


def remove_ccpa_compliant_rows(input_csv, output_csv):
    """
    Reads a CSV file, removes rows where 'CCPA_analysis' is 'CCPA COMPLIANT',
    and writes the result to a new CSV file.
    
    Parameters:
        input_csv (str): Path to the input CSV file.
        output_csv (str): Path where the filtered CSV will be saved.
        
    Returns:
        pd.DataFrame: The filtered DataFrame.
    """
    # Read the CSV into a DataFrame
    df = pd.read_csv(input_csv)
    
    # Filter out rows where CCPA_analysis equals "CCPA COMPLIANT"
    filtered_df = df[df['CCPA_analysis'] != "CCPA COMPLIANT"]
    
    # Write the filtered DataFrame to a new CSV file
    filtered_df.to_csv(output_csv, index=False)
    
    return filtered_df

# Example usage:
if __name__ == "__main__":
    input_csv_path = "../data/lead-list2-processed.csv"  # Update this path if needed
    output_csv_path = "../data/lead-list2-ccpa-noncompliants.csv"
    
    # Remove CCPA compliant rows and save the output
    filtered_data = remove_ccpa_compliant_rows(input_csv_path, output_csv_path)
    print(f"Filtered CSV saved to: {output_csv_path}")