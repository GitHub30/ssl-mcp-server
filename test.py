import asyncio
from server import _get_certificate_and_chain, _generate_self_signed_cert, _parse_certificate_pem
import json

def print_json(data):
    print(json.dumps(data, indent=2, default=str))

async def main():
    print("--- Testing generate_self_signed_cert ---")
    cert_data = _generate_self_signed_cert("test.local", 30)
    print("Generated Certificate:")
    print_json(cert_data)
    
    if "certificate_pem" in cert_data:
        print("\n--- Testing parse_certificate_pem ---")
        parsed = _parse_certificate_pem(cert_data["certificate_pem"])
        print("Parsed Certificate:")
        print_json(parsed)

    print("\n--- Testing get_certificate_and_chain (google.com) ---")
    # Note: This requires internet access
    try:
        chain_data = _get_certificate_and_chain("google.com")
        print("Certificate Chain Data:")
        # Print only the subject of the first cert to avoid huge output
        if "certificate" in chain_data:
            print("Leaf Certificate Subject:", chain_data["certificate"]["subject"])
        if "chain" in chain_data:
            print(f"Chain length: {len(chain_data['chain'])}")
            for i, cert in enumerate(chain_data["chain"]):
                 print(f"Chain[{i}] Subject:", cert["subject"])
    except Exception as e:
        print(f"Error fetching google.com cert: {e}")

if __name__ == "__main__":
    asyncio.run(main())
