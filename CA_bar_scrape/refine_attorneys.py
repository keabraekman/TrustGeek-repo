import pandas as pd

INPUT_FILE  = "la_attys_2025.xlsx"
OUTPUT_FILE = "la_attys_2025_clean.xlsx"

def main() -> None:
    # Read everything in as text so we don’t lose leading zeros or mix types
    df = pd.read_excel(INPUT_FILE, dtype=str)

    # Make sure NaNs become empty strings for uniform comparisons
    df["Phone"]  = df["Phone"].fillna("").str.strip()
    df["Email"]  = df["Email"].fillna("").str.strip()

    # Identify rows where phone is literally "0"  AND  email is empty
    rows_to_drop = (df["Phone"] == "0") & (df["Email"] == "")

    # Keep everything else
    df_clean = df.loc[~rows_to_drop]

    # Save the cleaned sheet
    df_clean.to_excel(OUTPUT_FILE, index=False)
    print(f"Removed {rows_to_drop.sum()} rows → saved {len(df_clean):,} rows to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()