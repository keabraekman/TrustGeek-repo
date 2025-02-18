from urllib.parse import urlparse


def clean_spreadsheet(df):
    """
    Takes a DataFrame, removes rows missing an email or website_url, and returns the cleaned DataFrame.
    """
    # Filter rows where 'email' and 'website_url' columns are not null
    df_clean = df.dropna(subset=['email', 'website_url'])
    # Optionally, remove rows with empty strings in those columns
    df_clean = df_clean[(df_clean['email'].str.strip() != '') & (df_clean['website_url'].str.strip() != '')]
    df_clean['website_url'] = df_clean['website_url'].apply(normalize_url)
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