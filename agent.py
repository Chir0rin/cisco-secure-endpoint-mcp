
import mcp
import requests
import os

CLIENT_ID = os.environ.get("SECURE_ENDPOINT_CLIENT_ID")
API_KEY = os.environ.get("SECURE_ENDPOINT_API_KEY")
BASE_URL = "https://api.amp.cisco.com/v1"
HEADERS = {"Accept": "application/json"}

@mcp.tool()
def list_computers(max_pages: int = 3, limit_per_page: int = 50) -> dict:
    """Retrieve a paginated list of devices registered in Cisco Secure Endpoint."""
    results = []
    url = f"{BASE_URL}/computers?limit={limit_per_page}"
    pages = 0

    while url and pages < max_pages:
        res = requests.get(url, auth=(CLIENT_ID, API_KEY), headers=HEADERS)
        res.raise_for_status()
        data = res.json()
        results.extend(data.get("data", []))
        url = data.get("metadata", {}).get("links", {}).get("next")
        pages += 1

    return {"computers": results}

@mcp.agent()
def main():
    return mcp.serve()
