"""
Sample Vulnerable Zcash Application.
Exposes hardcoded spending keys and insecure remote RPC.
"""

# CRITICAL SECURITY VULNERABILITY: Hardcoded spending key
BACKUP_SPENDING_KEY = "secret-extended-keytest1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"

def execute_unsafe_payment():
    # Insecure remote cleartext RPC
    node_rpc = "http://remote-node.zec-cloud.net:8232"
    print("Broadcasting from unsafe key:", BACKUP_SPENDING_KEY[:10])

if __name__ == "__main__":
    execute_unsafe_payment()
