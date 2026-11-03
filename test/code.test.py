import asyncio
from fastmcp.client import Client
import json

async def main():
    server_url = "http://localhost:3000/mcp"

    async with Client(server_url) as client:
        list_detections_result = await client.call_tool("get_detection", 
            {
                "id": "e2b36208-a364-11eb-8909-acde48001122"
            }
        )
        
        print(json.dumps(list_detections_result.structured_content))

if __name__ == "__main__":
    asyncio.run(main())