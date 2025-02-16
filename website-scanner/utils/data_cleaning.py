def clean_spreadsheet(df):
    """
    Takes a DataFrame, removes rows missing an email or website_url, and returns the cleaned DataFrame.
    """
    # Filter rows where 'email' and 'website_url' columns are not null
    df_clean = df.dropna(subset=['email', 'website_url'])
    # Optionally, remove rows with empty strings in those columns
    df_clean = df_clean[(df_clean['email'].str.strip() != '') & (df_clean['website_url'].str.strip() != '')]
    return df_clean
