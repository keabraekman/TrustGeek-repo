from urllib.parse import urlparse


def clean_spreadsheet(df):
    """
    Takes a DataFrame, removes rows missing an Email or Company Website Full, and returns the cleaned DataFrame.
    """
    # Filter rows where 'Email' and 'Company Website Full' columns are not null
    df_clean = df.dropna(subset=['Email', 'Company Website Full'])
    df_clean = df_clean[
        (df_clean['Email'].str.strip() != '') &
        (df_clean['Company Website Full'].str.strip() != '')
    ]
    
    # Remove rows where MillionVerifier Status is not 'good'
    df_clean = remove_not_good_millionverifier_status(df_clean)
    
    # Normalize URLs
    df_clean['Company Website Full'] = df_clean['Company Website Full'].apply(normalize_url)
    
    return df_clean


def normalize_url(url):
    """
    Normalizes a URL by extracting the hostname and ensuring it starts with 'www.'.
    If the hostname already starts with 'www.', it is returned as-is.
    """
    parsed = urlparse(url)
    # Use netloc if present, otherwise fallback to path
    hostname = parsed.netloc if parsed.netloc else parsed.path
    hostname = hostname.strip()
    if not hostname.startswith("www."):
        hostname = "www." + hostname
    return hostname

def remove_not_good_millionverifier_status(df):
    """
    Removes rows from the DataFrame where the 'MillionVerifier Status'
    column is not 'good'.
    """
    if 'MillionVerifier Status' not in df.columns:
        raise KeyError(
            "The 'MillionVerifier Status' column is missing from the DataFrame."
        )
    
    return df[df['MillionVerifier Status'] == 'good']

def remove_compliants(df):
    """
    Removes rows from the DataFrame where:
      - 'website_vulnerabilities' is empty (either NaN or an empty string), AND
      - 'CCPA_analysis' equals 'CCPA COMPLIANT'
      
    Parameters:
        df (pandas.DataFrame): The input DataFrame.
        
    Returns:
        pandas.DataFrame: A DataFrame with the specified rows removed.
    """
    required_columns = ['website_vulnerabilities', 'CCPA_analysis']
    missing_columns = [col for col in required_columns if col not in df.columns]
    if missing_columns:
        raise KeyError(
            f"The following required column(s) are missing from the DataFrame: {missing_columns}. "
            f"Available columns are: {list(df.columns)}"
        )

    # Build condition to identify rows to remove
    condition = (
        (df['website_vulnerabilities'].isna() | (df['website_vulnerabilities'] == "")) &
        (df['CCPA_analysis'] == "CCPA COMPLIANT")
    )
    
    # Return the DataFrame with rows that meet the condition removed
    return df[~condition]