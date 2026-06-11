from fastapi import FastAPI
import uvicorn

app = FastAPI()

# Global state to simulate failures
is_healthy = False


@app.get("/api/v1/query")
def query_prometheus(query: str):
    """Mocks the Prometheus query range API."""
    global is_healthy

    # If the query asks for 5xx rates
    if "sum(rate(http_requests_total{status=~'5..'}" in query:
        if not is_healthy:
            # Simulate a failing state (e.g., 12.4% error rate)
            error_rate = 0.124
        else:
            # Simulate a healthy post-remediation state (e.g., 1.2% error rate)
            error_rate = 0.012

        return {
            "status": "success",
            "data": {
                "resultType": "vector",
                "result": [{"value": [1681200000, str(error_rate)]}],
            },
        }
    return {"status": "success", "data": {"result": []}}


@app.post("/simulate/heal")
def heal_service():
    global is_healthy
    is_healthy = True
    return {"status": "simulation set to healthy"}


@app.post("/simulate/fail")
def fail_service():
    global is_healthy
    is_healthy = False
    return {"status": "simulation set to failing"}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=9090)
