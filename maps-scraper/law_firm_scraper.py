import os
from dotenv import load_dotenv
import googlemaps
import time
import csv

load_dotenv()
API_KEY = os.getenv("GOOGLE_MAPS_API_KEY")
gmaps = googlemaps.Client(key=API_KEY)
# example.env

# Convert address to lat/lng
def geocode_address(address):
    geo = gmaps.geocode(address)
    return geo[0]['geometry']['location']['lat'], geo[0]['geometry']['location']['lng']

# Generate grid points around the center
def generate_grid(center_lat, center_lng, miles=3, step_miles=1):
    step_deg = 0.015 * step_miles
    range_n = int(miles / step_miles)
    return [(center_lat + dy * step_deg, center_lng + dx * step_deg)
            for dx in range(-range_n, range_n + 1)
            for dy in range(-range_n, range_n + 1)]

# Search law firms near a coordinate
def search_law_firms_near(lat, lng):
    results = []
    next_page_token = None
    while True:
        response = gmaps.places(
            query="law firm",
            location=(lat, lng),
            radius=1600,
            type='lawyer',
            page_token=next_page_token
        )
        results.extend(response.get('results', []))
        next_page_token = response.get('next_page_token')
        if not next_page_token:
            break
        time.sleep(2)
    return results

# Filter out law firms that have a website and collect phone numbers
def filter_firms_without_website(places):
    firms = []
    for place in places:
        place_id = place['place_id']
        try:
            details = gmaps.place(place_id=place_id, fields=["name", "formatted_address", "website", "formatted_phone_number"])
            result = details.get("result", {})
            if not result.get("website"):
                firms.append({
                    "name": result.get("name"),
                    "address": result.get("formatted_address"),
                    "phone": result.get("formatted_phone_number", "N/A")
                })
        except Exception as e:
            print(f"Error with place_id {place_id}: {e}")
        time.sleep(0.1)
    return firms

# Save results to CSV
def export_to_csv(firms, filename="law_firms_no_website.csv"):
    with open(filename, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=["name", "address", "phone"])
        writer.writeheader()
        for firm in firms:
            writer.writerow(firm)
    print(f"\n📁 Exported {len(firms)} firms to: {filename}")

# Main execution
if __name__ == "__main__":
    center_address = "2476 Glencoe Ave, Los Angeles, CA"
    center_lat, center_lng = geocode_address(center_address)

    print(f"Center coordinates: {center_lat}, {center_lng}")
    grid_points = generate_grid(center_lat, center_lng, miles=3, step_miles=1)

    print("Collecting law firms...")
    all_places = {}
    for lat, lng in grid_points:
        print(f"Searching around {lat:.4f}, {lng:.4f}")
        try:
            firms = search_law_firms_near(lat, lng)
            for firm in firms:
                all_places[firm['place_id']] = firm
        except Exception as e:
            print(f"Error during search: {e}")

    print(f"Found {len(all_places)} unique law firms.")
    print("Filtering firms without websites...")

    firms_no_website = filter_firms_without_website(list(all_places.values()))

    print(f"\n✅ Law firms near {center_address} without a website:\n")
    for firm in firms_no_website:
        print(f"- {firm['name']} — {firm['address']} — 📞 {firm['phone']}")

    export_to_csv(firms_no_website)
