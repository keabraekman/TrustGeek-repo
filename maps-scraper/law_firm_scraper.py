import os
import time
import csv
from dotenv import load_dotenv
import googlemaps

# ── CONFIGURE THESE ────────────────────────────────────────────────
DESIRED_LEADS = 100   # stop once we have this many no-website firms
SURVEY_MILES  = 10     # how far (in miles) from the center to sweep
STEP_MILES    = 0.5     # grid spacing (miles)
POINT_RADIUS  = 1200  # search radius per point (meters)
# ───────────────────────────────────────────────────────────────────

load_dotenv()
gmaps = googlemaps.Client(key=os.getenv("GOOGLE_MAPS_API_KEY"))

def geocode(addr):
    loc = gmaps.geocode(addr)[0]['geometry']['location']
    return loc['lat'], loc['lng']

def generate_grid(lat0, lng0, survey_miles, step_miles):
    deg_per_mile = 0.0145
    step_deg     = deg_per_mile * step_miles
    n            = int(survey_miles / step_miles)
    for ix in range(-n, n+1):
        for iy in range(-n, n+1):
            # hex‐offset every other row
            lon = lng0 + ix*step_deg + (iy % 2)*step_deg/2
            lat = lat0 + iy*step_deg
            yield lat, lon

def places_text_search(lat, lng, radius_m):
    """Yields each place result from all pages."""
    next_tok = None
    while True:
        resp = gmaps.places(
            query="law firm",
            location=(lat, lng),
            radius=radius_m,
            page_token=next_tok
        )
        hits = resp.get("results", [])
        print(f"    → page returned {len(hits)} hits")
        for h in hits:
            yield h
        next_tok = resp.get("next_page_token")
        if not next_tok:
            break
        time.sleep(2)

def check_and_collect(pid, seen, output):
    """Check detail for one place_id, add to output if no website."""
    if pid in seen:
        return False
    seen.add(pid)
    det = gmaps.place(
        place_id=pid,
        fields=["name","formatted_address","website","formatted_phone_number"]
    )["result"]
    if not det.get("website"):
        output.append({
            "name":    det.get("name"),
            "address": det.get("formatted_address"),
            "phone":   det.get("formatted_phone_number", "N/A")
        })
        return True
    return False

def export_csv(data, fname="law_firms_no_website.csv"):
    with open(fname, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["name","address","phone"])
        w.writeheader()
        w.writerows(data)
    print(f"\n📁 Exported {len(data)} leads → {fname}")

if __name__=="__main__":
    center_addr = "2476 Glencoe Ave, Los Angeles, CA"
    lat0, lng0 = geocode(center_addr)
    print(f"Center at {lat0:.6f}, {lng0:.6f}")
    print(f"Target: {DESIRED_LEADS} no-website firms.\n")

    seen_ids = set()
    no_site  = []
    grid_pts = list(generate_grid(lat0, lng0, SURVEY_MILES, STEP_MILES))

    for i, (lat, lon) in enumerate(grid_pts, 1):
        print(f"[{i}/{len(grid_pts)}] Searching around {lat:.4f}, {lon:.4f}")
        for place in places_text_search(lat, lon, POINT_RADIUS):
            pid = place["place_id"]
            # optional: print small progress
            if len(no_site) % 10 == 0 and pid not in seen_ids:
                print(f"      • found {len(no_site)} so far…")
            added = check_and_collect(pid, seen_ids, no_site)
            if added:
                print(f"      ✅ #{len(no_site)}: {place['name']}")
                if len(no_site) >= DESIRED_LEADS:
                    break
        if len(no_site) >= DESIRED_LEADS:
            print("\n🎯 Reached target, stopping early!")
            break

    print(f"\n✅ Collected {len(no_site)} law firms without websites.")
    export_csv(no_site)
