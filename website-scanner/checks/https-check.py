import pandas as pd
import argparse

def check_https(url):
    """
    Check if a given URL uses HTTPS.
    
    Args:
        url (str): The website URL.
        
    Returns:
        bool: True if the URL starts with 'https://', otherwise False.
    """
    if isinstance(url, str) and url.lower().startswith("https://"):
        return True
    return False

def main():
    parser = argparse.ArgumentParser(
        description="Check for lack of HTTPS/SSL encryption in website URLs from a CSV file."
    )
    parser.add_argument(
        "--input",
        "-i",
        type=str,
        default="data/lead-list1.csv",
        help="Path to the input CSV file."
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default="data/lead-list1-https-checked.csv",
        help="Path to the output CSV file with HTTPS check results."
    )
    args = parser.parse_args()
    
    # Load the CSV file
    try:
        df = pd.read_csv(args.input)
    except Exception as e:
        print(f"Error reading the CSV file: {e}")
        return
    
    # Check that the CSV contains a 'website' column
    if 'website' not in df.columns:
        print("Error: The input CSV does not contain a 'website' column.")
        return
    
    # Add a new column indicating whether the website uses HTTPS
    df['uses_https'] = df['website'].apply(check_https)
    
    # Summary of HTTPS usage
    total = len(df)
    insecure_count = len(df[df['uses_https'] == False])
    print(f"Out of {total} records, {insecure_count} do NOT use HTTPS/SSL encryption.")
    
    # Optionally, you could also print out the insecure sites:
    insecure_sites = df[df['uses_https'] == False]
    if not insecure_sites.empty:
        print("Websites not using HTTPS:")
        for url in insecure_sites['website']:
            print(url)
    
    # Save the results to a new CSV file
    try:
        df.to_csv(args.output, index=False)
        print(f"Updated CSV file saved to {args.output}")
    except Exception as e:
        print(f"Error saving the output CSV file: {e}")

if __name__ == "__main__":
    main()
