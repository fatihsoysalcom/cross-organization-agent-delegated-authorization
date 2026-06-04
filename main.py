import hmac
import hashlib
import json
import time
import base64

# --- Configuration (Simulates pre-shared secrets between organizations) ---
# In a real-world scenario, these would be securely exchanged and managed.
ORG_SHARED_SECRET_KEY = b"super_secret_key_between_org_a_and_b"

# --- Organization A (The Principal) ---
class OrganizationA:
    def __init__(self, name="OrgA"):
        self.name = name

    def _sign_token(self, payload: dict) -> str:
        """Signs the payload using HMAC and a shared secret."""
        # Convert payload to a canonical JSON string for consistent signing
        payload_str = json.dumps(payload, sort_keys=True, separators=(',', ':'))
        # Generate HMAC signature
        signature = hmac.new(
            ORG_SHARED_SECRET_KEY,
            payload_str.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        # Combine base64-encoded payload and signature into a token string
        return f"{base64.urlsafe_b64encode(payload_str.encode('utf-8')).decode('utf-8')}.{signature}"

    def delegate_authority(self, agent_id: str, scope: list, duration_seconds: int = 3600) -> str:
        """
        Delegates authority to an agent by issuing a signed token.
        This simulates OrgA trusting its agent and authorizing it for specific actions
        on behalf of OrgA, to be performed with OrgB.
        """
        expiration_time = int(time.time()) + duration_seconds
        payload = {
            "iss": self.name, # Issuer (Organization A)
            "sub": agent_id,  # Subject (Agent A)
            "scope": scope,   # Delegated permissions
            "exp": expiration_time # Expiration time
        }
        delegation_token = self._sign_token(payload)
        print(f"[{self.name}] Issued delegation token for agent '{agent_id}' with scope '{scope}'.")
        return delegation_token

# --- Agent A (The Delegated Entity) ---
class AgentA:
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.delegation_token = None

    def receive_token(self, token: str):
        """Agent receives the delegated authorization token from its principal (OrgA)."""
        self.delegation_token = token
        print(f"[{self.agent_id}] Received delegation token.")

    def request_data_from_org_b(self, org_b_service):
        """Agent attempts to access data from OrgB using the token."""
        if not self.delegation_token:
            print(f"[{self.agent_id}] No delegation token available. Cannot make request.")
            return

        print(f"[{self.agent_id}] Requesting data from OrgB using token...")
        org_b_service.handle_request(self.delegation_token, self.agent_id)

# --- Organization B (The Resource Server) ---
class OrganizationBService:
    def __init__(self, name="OrgBService"):
        self.name = name
        self.available_data = {
            "sales_data": {"Q1": 1000, "Q2": 1200, "Q3": 1500},
            "customer_info": {"id": "C1", "name": "John Doe", "email": "john.doe@example.com"}
        }

    def _verify_token(self, token: str) -> dict | None:
        """Verifies the token's signature and validity using the shared secret."""
        try:
            encoded_payload, signature = token.split('.')
            payload_str = base64.urlsafe_b64decode(encoded_payload).decode('utf-8')

            # Re-calculate signature to verify against the provided one
            expected_signature = hmac.new(
                ORG_SHARED_SECRET_KEY,
                payload_str.encode('utf-8'),
                hashlib.sha256
            ).hexdigest()

            # Crucial for security: compare signatures in a timing-attack safe manner
            if not hmac.compare_digest(expected_signature, signature):
                print(f"[{self.name}] Token verification failed: Invalid signature (token tampered or wrong key).")
                return None

            payload = json.loads(payload_str)

            # Check expiration time of the token
            if payload.get("exp") and payload["exp"] < int(time.time()):
                print(f"[{self.name}] Token verification failed: Token expired.")
                return None

            print(f"[{self.name}] Token verified successfully for agent '{payload.get('sub')}' from '{payload.get('iss')}'.")
            return payload

        except Exception as e:
            print(f"[{self.name}] Error verifying token: {e}")
            return None

    def handle_request(self, token: str, requesting_agent_id: str):
        """Handles an incoming request from an agent, verifying its delegated authorization."""
        print(f"[{self.name}] Received request from agent '{requesting_agent_id}'. Verifying token...")
        payload = self._verify_token(token)

        if not payload:
            print(f"[{self.name}] Access Denied: Invalid or expired token.")
            return

        # Optional but good practice: ensure the token is for the agent making the request
        if payload.get("sub") != requesting_agent_id:
            print(f"[{self.name}] Access Denied: Token issued for a different agent.")
            return

        # Check if the delegated scope allows the requested action
        requested_scope = "read:sales_data" # The specific action the agent is trying to perform
        if requested_scope in payload.get("scope", []):
            print(f"[{self.name}] Access Granted for '{requesting_agent_id}' to '{requested_scope}'.")
            data = self.available_data.get("sales_data")
            print(f"[{self.name}] Providing sales data: {data}")
            return data
        else:
            print(f"[{self.name}] Access Denied: Agent '{requesting_agent_id}' does not have '{requested_scope}' scope.")
            return None

# --- Main Execution Flow ---
if __name__ == "__main__":
    print("--- Simulating Cross-Organizational Delegated Authorization ---")

    # 1. Initialize organizations and agent
    org_a = OrganizationA()
    org_b_service = OrganizationBService()
    data_analysis_agent = AgentA("data_agent_123")

    print("\n--- Scenario 1: Successful Delegation and Access ---")
    # 2. Organization A delegates authority to its agent.
    #    OrgA issues a token allowing its agent to read sales data from OrgB.
    delegation_token_success = org_a.delegate_authority(
        agent_id=data_analysis_agent.agent_id,
        scope=["read:sales_data"], # Delegated scope
        duration_seconds=60 # Token valid for 60 seconds
    )

    # 3. Agent receives the token.
    data_analysis_agent.receive_token(delegation_token_success)

    # 4. Agent uses the token to request data from Organization B.
    data_analysis_agent.request_data_from_org_b(org_b_service)

    print("\n--- Scenario 2: Access Denied due to Insufficient Scope ---")
    # OrgA issues a token without the necessary scope for the requested action.
    delegation_token_no_scope = org_a.delegate_authority(
        agent_id=data_analysis_agent.agent_id,
        scope=["read:customer_info"], # Agent tries to read sales data, but only has customer_info scope
        duration_seconds=60
    )
    data_analysis_agent.receive_token(delegation_token_no_scope)
    data_analysis_agent.request_data_from_org_b(org_b_service)

    print("\n--- Scenario 3: Access Denied due to Expired Token ---")
    # OrgA issues a token that expires quickly.
    delegation_token_expired = org_a.delegate_authority(
        agent_id=data_analysis_agent.agent_id,
        scope=["read:sales_data"],
        duration_seconds=1 # Token valid for 1 second
    )
    data_analysis_agent.receive_token(delegation_token_expired)
    print("Waiting for token to expire (2 seconds)...")
    time.sleep(2) # Wait for the token to expire
    data_analysis_agent.request_data_from_org_b(org_b_service)

    print("\n--- Scenario 4: Access Denied due to Tampered Token (simulated) ---")
    # OrgA issues a valid token.
    delegation_token_tampered = org_a.delegate_authority(
        agent_id=data_analysis_agent.agent_id,
        scope=["read:sales_data"],
        duration_seconds=60
    )
    # Simulate tampering: an attacker modifies the payload (e.g., changes scope)
    # without being able to re-sign it correctly.
    parts = delegation_token_tampered.split('.')
    encoded_payload = parts[0]
    original_payload_dict = json.loads(base64.urlsafe_b64decode(encoded_payload).decode('utf-8'))
    original_payload_dict["scope"] = ["write:sales_data"] # Agent tries to elevate privileges
    tampered_encoded_payload = base64.urlsafe_b64encode(json.dumps(original_payload_dict, sort_keys=True, separators=(',', ':')).encode('utf-8')).decode('utf-8')
    tampered_token = f"{tampered_encoded_payload}.{parts[1]}" # Signature remains original, thus invalid for new payload

    print(f"[Simulated Tamper] Agent '{data_analysis_agent.agent_id}' attempts to use a tampered token.")
    data_analysis_agent.receive_token(tampered_token)
    data_analysis_agent.request_data_from_org_b(org_b_service)
