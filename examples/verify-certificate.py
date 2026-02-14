import sys
import json
from openexecution_verify import OpenExecutionVerifier


def main():
    if len(sys.argv) < 2:
        print("Usage: python verify-certificate.py <certificate-id>")
        sys.exit(1)

    verifier = OpenExecutionVerifier()
    try:
        result = verifier.verify_certificate(sys.argv[1])
        print(json.dumps(result, indent=2))
        print(
            "Certificate is VALID" if result.get("valid") else "Certificate is INVALID"
        )
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
