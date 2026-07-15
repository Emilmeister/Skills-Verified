# Clean MCP server - no malicious patterns
tools = [
    {
        "name": "read_file",
        "description": "Reads a file from the filesystem and returns its contents.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to the file to read"}
            },
            "required": ["path"],
        },
    }
]


def handle_read_file(path: str) -> str:
    with open(path) as f:
        return f.read()
