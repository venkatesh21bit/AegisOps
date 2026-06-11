import asyncio
import os
from dotenv import load_dotenv
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

load_dotenv()

async def test_splunk_mcp():
    print("Testing Splunk MCP Connection...")
    # Set up server parameters
    server_params = StdioServerParameters(
        command=os.path.abspath(r".venv\Scripts\uvx.exe"),
        args=["mcp-server-splunk"],
        env=os.environ.copy()
    )
    
    try:
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                # Initialize the connection
                await session.initialize()
                
                # List available tools
                print("Connected! Listing tools...")
                tools = await session.list_tools()
                for tool in tools.tools:
                    print(f"- {tool.name}: {tool.description}")
                    
                print("\nSplunk MCP connection successful.")
                return True
    except Exception as e:
        print(f"Failed to connect to Splunk MCP: {e}")
        return False

if __name__ == "__main__":
    asyncio.run(test_splunk_mcp())
