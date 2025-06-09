import os
import time
import csv
from dotenv import load_dotenv
import googlemaps

# ── CONFIGURE THESE ────────────────────────────────────────────────
SURVEY_MILES = 10   # how far (in miles) from the center to sweep
# ────────────────────────────────────────────────────────────────────

load_dotenv()
gmaps = googlemaps.Client(key=os.getenv("GOOGLE_MAPS_API_KEY"))

def geocode(addr):
    loc = gmaps.geocode(addr)[0]['geometry']['location']
    return loc['lat'], loc['lng']

def places_nearby_high_schools(lat, lng, radius_m):
    """
    Yields each place result (all pages) where "high school" appears in the name.
    """
    next_tok = None
    while True:
        resp = gmaps.places_nearby(
            location=(lat, lng),
            radius=radius_m,
            type="school",      # restricts to schools (elementary, middle, high)
            page_token=next_tok
        )
        for result in resp.get("results", []):
            name = result.get("name", "").lower()
            if "high school" in name:
                yield result
        next_tok = resp.get("next_page_token")
        if not next_tok:
            break
        time.sleep(2)  # required delay before using next_page_token

def collect_school(pid, seen, output):
    """Fetches details (name, address, phone) for one place_id, appends to output."""
    if pid in seen:
        return
    seen.add(pid)
    det = gmaps.place(
        place_id=pid,
        fields=["name", "formatted_address", "formatted_phone_number"]
    )["result"]
    output.append({
        "name":    det.get("name", "N/A"),
        "address": det.get("formatted_address", "N/A"),
        "phone":   det.get("formatted_phone_number", "N/A")
    })

def export_csv(data, fname="high_schools_nearby.csv"):
    with open(fname, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["name", "address", "phone"])
        writer.writeheader()
        writer.writerows(data)
    print(f"\n📁 Exported {len(data)} schools → {fname}")

if __name__ == "__main__":
    center_addr = "2476 Glencoe Ave, Los Angeles, CA"
    lat0, lng0 = geocode(center_addr)
    radius_m = int(SURVEY_MILES * 1609.34)  # 1 mile ≈ 1609.34 meters

    print(f"Center at {lat0:.6f}, {lng0:.6f}")
    print(f"Searching for high schools within {SURVEY_MILES} miles (~{radius_m} m)...\n")

    seen_ids = set()
    schools = []

    for place in places_nearby_high_schools(lat0, lng0, radius_m):
        pid = place["place_id"]
        collect_school(pid, seen_ids, schools)

    print(f"\n✅ Collected {len(schools)} high schools.")
    export_csv(schools)
