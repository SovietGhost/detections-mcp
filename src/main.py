import csv
import io
import time
import urllib.request
from typing import Any, Optional
from uuid import UUID
from pydantic import BaseModel, Field
from fastmcp import FastMCP

# ---------------------------------------------------------------------------
# FastMCP Server Initialization
# ---------------------------------------------------------------------------
mcp = FastMCP(
    name="Splunk Detections",
    instructions=(
        "Read-only access to Splunk Security Content detection rules (research.splunk.com), "
        "so an AI assistant can browse and look them up."
    ),
)

# Cache management (1 hour TTL)
CACHE_TTL_SECONDS = 3600
_cache_timestamp: float = 0
_cache_data: list[dict[str, Any]] = []

SPLUNK_EXPORT_URL = (
    "https://research.splunk.com/detections_export.csv"
)


def split_list_cell(val: str) -> list[str]:
    """Splits newline-separated values inside a CSV cell."""
    if not val:
        return []
    return [line.strip() for line in val.splitlines() if line.strip()]


def load_detections() -> list[dict[str, Any]]:
    """Fetches CSV data, parses, and caches results for 1 hour."""
    global _cache_timestamp, _cache_data

    now = time.time()
    if _cache_data and (now - _cache_timestamp < CACHE_TTL_SECONDS):
        return _cache_data

    req = urllib.request.Request(
        SPLUNK_EXPORT_URL, headers={"Accept": "text/csv, */*"}
    )
    with urllib.request.urlopen(req, timeout=120) as response:
        csv_text = response.read().decode("utf-8")

    reader = csv.DictReader(io.StringIO(csv_text))
    rows = []

    for record in reader:
        # Process and normalize data format
        processed_row = {
            "id": record.get("id", ""),
            "version": int(record["version"]) if record.get("version") else 1,
            "creation_date": record.get("creation_date", "")[:10],
            "modification_date": record.get("modification_date", "")[:10],
            "author": record.get("author", ""),
            "status": record.get("status", ""),
            "type": record.get("type", ""),
            "description": record.get("description", ""),
            "data_source": split_list_cell(record.get("data_source", "")),
            "search": record.get("search", ""),
            "how_to_implement": record.get("how_to_implement", ""),
            "known_false_positives": record.get("known_false_positives", ""),
            "references": split_list_cell(record.get("references", "")),
            "analytic_story": split_list_cell(record.get("analytic_story", "")),
            "asset_type": record.get("asset_type", ""),
            "mitre_attack_id": split_list_cell(
                record.get("mitre_attack_id", "")
            ),
            "product": split_list_cell(record.get("product", "")),
            "category": record.get("category", ""),
            "security_domain": record.get("security_domain", ""),
            "tests_data": split_list_cell(record.get("tests.data", "")),
        }
        rows.append(processed_row)

    _cache_data = rows
    _cache_timestamp = now
    return _cache_data


# ---------------------------------------------------------------------------
# MCP Tools
# ---------------------------------------------------------------------------


@mcp.tool(
    name="list_detections",
    description="Lists Splunk detection rules as { id, description } pairs, one page at a time.",
)
def list_detections(
    page: int = Field(0, ge=0, description="0-based page index (default 0)"),
    limit: int = Field(
        10, ge=1, le=100, description="Detections per page, 1-100 (default 10)"
    ),
) -> dict[str, Any]:
    try:
        rows = load_detections()
    except Exception as err:
        return {"error": f"Could not download Splunk detections export: {err}"}

    total_pages = (len(rows) + limit - 1) // limit
    start = page * limit
    end = start + limit
    page_items = rows[start:end]

    return {
        "page": page,
        "limit": limit,
        "total": len(rows),
        "totalPages": total_pages,
        "hasMore": page + 1 < total_pages,
        "items": [
            {"id": item["id"], "description": item["description"]}
            for item in page_items
        ],
    }


@mcp.tool(
    name="get_detection",
    description="Returns the full Splunk detection rule for one id (SPL search, MITRE IDs, false positives, etc.).",
)
def get_detection(
    id: str = Field(..., min_length=1, description="Detection UUID"),
) -> dict[str, Any]:
    try:
        rows = load_detections()
    except Exception as err:
        return {"error": f"Could not download Splunk detections export: {err}"}

    matched = next((row for row in rows if row["id"] == id), None)
    if not matched:
        return {
            "error": f"No detection found with id '{id}'. Use list_detections to browse valid ids."
        }

    return {"detection": matched}


# ---------------------------------------------------------------------------
# Entrypoint: Run FastMCP Server on Port 3000
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # Runs an HTTP / SSE server at http://localhost:3000/mcp
    mcp.run(transport="http", host="0.0.0.0", port=3000)