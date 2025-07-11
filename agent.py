import mcp
import requests
import os
from dotenv import load_dotenv

load_dotenv()

# Authentication information (retrieved from environment variables)
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

@mcp.tool()
def list_events(max_pages: int = 3, limit_per_page: int = 50) -> dict:
    """Retrieve a paginated list of recent security events."""
    results = []
    url = f"{BASE_URL}/events?limit={limit_per_page}"
    pages = 0

    while url and pages < max_pages:
        res = requests.get(url, auth=(CLIENT_ID, API_KEY), headers=HEADERS)
        res.raise_for_status()
        data = res.json()
        results.extend(data.get("data", []))
        url = data.get("metadata", {}).get("links", {}).get("next")
        pages += 1

    return {"events": results}

@mcp.tool()
def isolate_device(computer_guid: str) -> dict:
    """Isolate the device with the specified GUID from the network."""
    url = f"{BASE_URL}/computers/{computer_guid}/isolation"
    res = requests.post(url, auth=(CLIENT_ID, API_KEY), headers=HEADERS)
    res.raise_for_status()
    return {"status": "success", "message": f"Device {computer_guid} isolated successfully."}

@mcp.tool()
def unisolate_device(computer_guid: str) -> dict:
    """Lift the network isolation of the device with the specified GUID."""
    url = f"{BASE_URL}/computers/{computer_guid}/isolation"
    res = requests.delete(url, auth=(CLIENT_ID, API_KEY), headers=HEADERS)
    res.raise_for_status()
    return {"status": "success", "message": f"Device {computer_guid} unisolated successfully."}

@mcp.tool()
def get_isolation_status(computer_guid: str) -> dict:
    """Get the current isolation status of the device with the specified GUID."""
    url = f"{BASE_URL}/computers/{computer_guid}/isolation"
    res = requests.get(url, auth=(CLIENT_ID, API_KEY), headers=HEADERS)
    res.raise_for_status()
    return res.json()

@mcp.agent()
def main():
    return mcp.serve()
