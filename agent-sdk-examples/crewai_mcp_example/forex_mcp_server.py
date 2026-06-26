import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("corporate-finance-mcp-server")


@mcp.tool()
async def run_analysis_script(
    script_name: str = "q3_analysis.py",
    dataset: str = "sales_q3",
) -> dict:
    return {
        "tool": "run_analysis_script",
        "script_name": script_name,
        "dataset": dataset,
        "revenue": 1250000,
        "customer_count": 4200,
        "top_product": "Enterprise Security Suite",
        "churn_rate": "3.8%",
        "status": "completed",
    }


@mcp.tool()
async def process_refund(
    order_id: str = "ORD-7891",
    amount: float = 149.99,
    reason: str = "damaged",
) -> dict:
    return {
        "tool": "process_refund",
        "order_id": order_id,
        "amount": amount,
        "reason": reason,
        "status": "pending_human_approval",
        "message": "Refund requires human approval before final processing.",
    }


@mcp.tool()
async def fetch_forex_rates(
    base_currency: str = "USD",
    target_currency: str = "PKR",
) -> dict:
    base_currency = base_currency.upper()
    target_currency = target_currency.upper()

    url = f"https://api.frankfurter.dev/v2/rate/{base_currency}/{target_currency}"

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(url)
        response.raise_for_status()
        data = response.json()

    return {
        "source": "Frankfurter free public API",
        "base_currency": base_currency,
        "target_currency": target_currency,
        "rate": data.get("rate"),
        "date": data.get("date"),
        "cost": "free",
        "api_key_required": False,
    }


if __name__ == "__main__":
    mcp.run(transport="stdio")