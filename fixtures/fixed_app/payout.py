"""
Sample Hardened Zcash Application.
Uses ZecShield air-gapped MCP workflow, strict loopback, and zero hardcoded keys.
"""

import os

# Secrets are NEVER hardcoded in source code or model prompts.
# Spending keys are managed in a hardware module or out-of-band vault.
NODE_RPC_URL = os.environ.get("ZEBRAD_RPC_URL", "http://127.0.0.1:8181")

def execute_hardened_payment():
    print(f"Connecting securely via air-gapped loopback: {NODE_RPC_URL}")

if __name__ == "__main__":
    execute_hardened_payment()
