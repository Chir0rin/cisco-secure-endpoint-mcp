#!/usr/bin/env python3
"""
Cisco Secure Endpoint MCP Server

This server provides MCP tools for interacting with Cisco Secure Endpoint (formerly AMP for Endpoints) API.
It allows you to manage devices, retrieve security events, and perform isolation operations.

Environment Variables Required:
- SECURE_ENDPOINT_CLIENT_ID: Your Cisco Secure Endpoint Client ID
- SECURE_ENDPOINT_API_KEY: Your Cisco Secure Endpoint API Key

Author: Hironobu Morishita
License: Hironobu Morishita
"""

import asyncio
import json
import os
import sys
from typing import Any, Sequence

import requests
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configuration
CLIENT_ID = os.environ.get("SECURE_ENDPOINT_CLIENT_ID")
API_KEY = os.environ.get("SECURE_ENDPOINT_API_KEY")
BASE_URL = "https://api.amp.cisco.com/v1"
HEADERS = {"Accept": "application/json"}

# MCP imports
try:
    from mcp.server import NotificationOptions, Server
    from mcp.server.models import InitializationOptions
    import mcp.server.stdio
    import mcp.types as types
except ImportError:
    print("Error: MCP library not installed. Please install with: pip install mcp")
    sys.exit(1)

# Initialize MCP server
server = Server("cisco-secure-endpoint")

@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """Return the list of available tools."""
    return [
        types.Tool(
            name="list_computers",
            description="Retrieve a paginated list of devices registered in Cisco Secure Endpoint",
            inputSchema={
                "type": "object",
                "properties": {
                    "max_pages": {
                        "type": "integer",
                        "description": "Maximum number of pages to retrieve",
                        "default": 3,
                        "minimum": 1,
                        "maximum": 10
                    },
                    "limit_per_page": {
                        "type": "integer", 
                        "description": "Number of devices per page",
                        "default": 50,
                        "minimum": 1,
                        "maximum": 500
                    }
                }
            }
        ),
        types.Tool(
            name="list_events",
            description="Retrieve a paginated list of recent security events",
            inputSchema={
                "type": "object",
                "properties": {
                    "max_pages": {
                        "type": "integer",
                        "description": "Maximum number of pages to retrieve", 
                        "default": 3,
                        "minimum": 1,
                        "maximum": 10
                    },
                    "limit_per_page": {
                        "type": "integer",
                        "description": "Number of events per page",
                        "default": 50,
                        "minimum": 1,
                        "maximum": 500
                    }
                }
            }
        ),
        types.Tool(
            name="isolate_device",
            description="Isolate a device from the network to prevent further compromise",
            inputSchema={
                "type": "object",
                "properties": {
                    "computer_guid": {
                        "type": "string",
                        "description": "The GUID of the device to isolate"
                    }
                },
                "required": ["computer_guid"]
            }
        ),
        types.Tool(
            name="unisolate_device", 
            description="Remove network isolation from a device",
            inputSchema={
                "type": "object",
                "properties": {
                    "computer_guid": {
                        "type": "string",
                        "description": "The GUID of the device to unisolate"
                    }
                },
                "required": ["computer_guid"]
            }
        ),
        types.Tool(
            name="get_isolation_status",
            description="Check the current isolation status of a device",
            inputSchema={
                "type": "object", 
                "properties": {
                    "computer_guid": {
                        "type": "string",
                        "description": "The GUID of the device to check"
                    }
                },
                "required": ["computer_guid"]
            }
        )
    ]

@server.call_tool()
async def handle_call_tool(name: str, arguments: dict | None) -> list[types.TextContent]:
    """Handle tool execution requests."""
    if not CLIENT_ID or not API_KEY:
        return [types.TextContent(
            type="text",
            text="Error: Missing environment variables. Please set SECURE_ENDPOINT_CLIENT_ID and SECURE_ENDPOINT_API_KEY"
        )]
    
    try:
        if name == "list_computers":
            result = await _list_computers(
                max_pages=arguments.get("max_pages", 3) if arguments else 3,
                limit_per_page=arguments.get("limit_per_page", 50) if arguments else 50
            )
        elif name == "list_events":
            result = await _list_events(
                max_pages=arguments.get("max_pages", 3) if arguments else 3,
                limit_per_page=arguments.get("limit_per_page", 50) if arguments else 50
            )
        elif name == "isolate_device":
            if not arguments or "computer_guid" not in arguments:
                raise ValueError("computer_guid parameter is required")
            result = await _isolate_device(arguments["computer_guid"])
        elif name == "unisolate_device":
            if not arguments or "computer_guid" not in arguments:
                raise ValueError("computer_guid parameter is required")
            result = await _unisolate_device(arguments["computer_guid"])
        elif name == "get_isolation_status":
            if not arguments or "computer_guid" not in arguments:
                raise ValueError("computer_guid parameter is required")
            result = await _get_isolation_status(arguments["computer_guid"])
        else:
            raise ValueError(f"Unknown tool: {name}")
        
        return [types.TextContent(
            type="text", 
            text=json.dumps(result, indent=2, ensure_ascii=False)
        )]
        
    except Exception as e:
        return [types.TextContent(
            type="text",
            text=f"Error executing {name}: {str(e)}"
        )]

async def _list_computers(max_pages: int = 3, limit_per_page: int = 50) -> dict:
    """Retrieve a paginated list of devices registered in Cisco Secure Endpoint."""
    results = []
    url = f"{BASE_URL}/computers?limit={limit_per_page}"
    pages = 0

    while url and pages < max_pages:
        response = requests.get(url, auth=(CLIENT_ID, API_KEY), headers=HEADERS)
        response.raise_for_status()
        data = response.json()
        results.extend(data.get("data", []))
        url = data.get("metadata", {}).get("links", {}).get("next")
        pages += 1

    return {
        "total_devices": len(results),
        "pages_retrieved": pages,
        "computers": results
    }

async def _list_events(max_pages: int = 3, limit_per_page: int = 50) -> dict:
    """Retrieve a paginated list of recent security events."""
    results = []
    url = f"{BASE_URL}/events?limit={limit_per_page}"
    pages = 0

    while url and pages < max_pages:
        response = requests.get(url, auth=(CLIENT_ID, API_KEY), headers=HEADERS)
        response.raise_for_status()
        data = response.json()
        results.extend(data.get("data", []))
        url = data.get("metadata", {}).get("links", {}).get("next")
        pages += 1

    return {
        "total_events": len(results),
        "pages_retrieved": pages,
        "events": results
    }

async def _isolate_device(computer_guid: str) -> dict:
    """Isolate the device with the specified GUID from the network."""
    url = f"{BASE_URL}/computers/{computer_guid}/isolation"
    response = requests.post(url, auth=(CLIENT_ID, API_KEY), headers=HEADERS)
    response.raise_for_status()
    return {
        "status": "success",
        "message": f"Device {computer_guid} isolated successfully",
        "computer_guid": computer_guid
    }

async def _unisolate_device(computer_guid: str) -> dict:
    """Lift the network isolation of the device with the specified GUID."""
    url = f"{BASE_URL}/computers/{computer_guid}/isolation"
    response = requests.delete(url, auth=(CLIENT_ID, API_KEY), headers=HEADERS)
    response.raise_for_status()
    return {
        "status": "success", 
        "message": f"Device {computer_guid} unisolated successfully",
        "computer_guid": computer_guid
    }

async def _get_isolation_status(computer_guid: str) -> dict:
    """Get the current isolation status of the device with the specified GUID."""
    url = f"{BASE_URL}/computers/{computer_guid}/isolation"
    response = requests.get(url, auth=(CLIENT_ID, API_KEY), headers=HEADERS)
    response.raise_for_status()
    data = response.json()
    return {
        "computer_guid": computer_guid,
        "isolation_status": data
    }

async def main():
    """Run the MCP server using stdio transport."""
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="cisco-secure-endpoint",
                server_version="1.0.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={}
                )
            )
        )

if __name__ == "__main__":
    asyncio.run(main())
