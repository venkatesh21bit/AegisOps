import asyncio
from aegisops.integrations.otel_filter_engine import otel_apply_filter_configmap

async def main():
    print("Testing OTel Filter ConfigMap Deployment Tool...")
    result = await otel_apply_filter_configmap.ainvoke({
        "service_name": "payment-service",
        "incident_id": "INC-TEST-999",
        "noise_threshold": 5,
        "namespace": "default"
    })
    print("\nResult:")
    print(result)

if __name__ == '__main__':
    asyncio.run(main())
