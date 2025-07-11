import requests
import os
from dotenv import load_dotenv
from mcp.server import Server
from mcp.types import TextContent, Tool
import asyncio
import json

load_dotenv()

# Authentication information (retrieved from environment variables)
CLIENT_ID = os.environ.get("SECURE_ENDPOINT_CLIENT_ID")
API_KEY = os.environ.get("SECURE_ENDPOINT_API_KEY")
BASE_URL = "https://api.amp.cisco.com/v1"
HEADERS = {"Accept": "application/json"}

# MCPサーバーの初期化
server = Server("cisco-secure-endpoint")

@server.list_tools()
async def handle_list_tools() -> list[Tool]:
    """利用可能なツールのリストを返す"""
    return [
        Tool(
            name="list_computers",
            description="Retrieve a paginated list of devices registered in Cisco Secure Endpoint.",
            inputSchema={
                "type": "object",
                "properties": {
                    "max_pages": {"type": "integer", "default": 3},
                    "limit_per_page": {"type": "integer", "default": 50}
                }
            }
        ),
        Tool(
            name="list_events",
            description="Retrieve a paginated list of recent security events.",
            inputSchema={
                "type": "object",
                "properties": {
                    "max_pages": {"type": "integer", "default": 3},
                    "limit_per_page": {"type": "integer", "default": 50}
                }
            }
        ),
        Tool(
            name="isolate_device",
            description="Isolate the device with the specified GUID from the network.",
            inputSchema={
                "type": "object",
                "properties": {
                    "computer_guid": {"type": "string", "description": "The GUID of the device to isolate"}
                },
                "required": ["computer_guid"]
            }
        ),
        Tool(
            name="unisolate_device",
            description="Lift the network isolation of the device with the specified GUID.",
            inputSchema={
                "type": "object",
                "properties": {
                    "computer_guid": {"type": "string", "description": "The GUID of the device to unisolate"}
                },
                "required": ["computer_guid"]
            }
        ),
        Tool(
            name="get_isolation_status",
            description="Get the current isolation status of the device with the specified GUID.",
            inputSchema={
                "type": "object",
                "properties": {
                    "computer_guid": {"type": "string", "description": "The GUID of the device to check"}
                },
                "required": ["computer_guid"]
            }
        )
    ]

@server.call_tool()
async def handle_call_tool(name: str, arguments: dict) -> list[TextContent]:
    """ツールの実行を処理"""
    try:
        if name == "list_computers":
            result = list_computers(
                max_pages=arguments.get("max_pages", 3),
                limit_per_page=arguments.get("limit_per_page", 50)
            )
        elif name == "list_events":
            result = list_events(
                max_pages=arguments.get("max_pages", 3),
                limit_per_page=arguments.get("limit_per_page", 50)
            )
        elif name == "isolate_device":
            result = isolate_device(arguments["computer_guid"])
        elif name == "unisolate_device":
            result = unisolate_device(arguments["computer_guid"])
        elif name == "get_isolation_status":
            result = get_isolation_status(arguments["computer_guid"])
        else:
            raise ValueError(f"Unknown tool: {name}")
        
        return [TextContent(type="text", text=json.dumps(result, indent=2))]
    except Exception as e:
        return [TextContent(type="text", text=f"Error: {str(e)}")]

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

def isolate_device(computer_guid: str) -> dict:
    """Isolate the device with the specified GUID from the network."""
    url = f"{BASE_URL}/computers/{computer_guid}/isolation"
    res = requests.post(url, auth=(CLIENT_ID, API_KEY), headers=HEADERS)
    res.raise_for_status()
    return {"status": "success", "message": f"Device {computer_guid} isolated successfully."}

def unisolate_device(computer_guid: str) -> dict:
    """Lift the network isolation of the device with the specified GUID."""
    url = f"{BASE_URL}/computers/{computer_guid}/isolation"
    res = requests.delete(url, auth=(CLIENT_ID, API_KEY), headers=HEADERS)
    res.raise_for_status()
    return {"status": "success", "message": f"Device {computer_guid} unisolated successfully."}

def get_isolation_status(computer_guid: str) -> dict:
    """Get the current isolation status of the device with the specified GUID."""
    url = f"{BASE_URL}/computers/{computer_guid}/isolation"
    res = requests.get(url, auth=(CLIENT_ID, API_KEY), headers=HEADERS)
    res.raise_for_status()
    return res.json()

async def main():
    """MCPサーバーを起動"""
    import mcp.server.stdio
    from mcp.server.models import InitializationOptions
    
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="cisco-secure-endpoint",
                server_version="1.0.0",
                capabilities=server.get_capabilities()
            ),
        )

if __name__ == "__main__":
    asyncio.run(main())
