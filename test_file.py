
# Simple test program that demonstrates the Account Management Service works end-to-end.
# Deployed base URL on render(choose render because i will like to further develop this microservice):
BASE_URL = "https://account-management-service-1.onrender.com"

import requests
import json
import time

TIMEOUT_SEC = 20
DELAY_BETWEEN_CALLS = 5

def pretty(obj):
    return json.dumps(obj, indent=2)


def call(method, path, *, headers=None, body=None):
    url = f"{BASE_URL}{path}"
    headers = headers or {}

    if body is not None:
        # ensure JSON requests have a content-type
        headers.setdefault("Content-Type", "application/json")

    resp = requests.request(
        method=method,
        url=url,
        headers=headers,
        json=body,
        timeout=TIMEOUT_SEC
    )

    try:
        data = resp.json()
    except ValueError:
        data = {"status": "error", "error": {"code": "NON_JSON", "message": resp.text}}

    return resp.status_code, data


def main():
    print("=" * 70)
    print("ACCOUNT MANAGEMENT SERVICE TEST")
    print(f"BASE_URL = {BASE_URL}")
    print("=" * 70)

    # Use a unique email each run so register can succeed repeatedly
    unique = int(time.time())
    email = f"testuser_{unique}@example.com"
    password = "Password123"
    full_name = "Test User"
    dob = "1995-04-12"
    address = "100 Main Street"

    # 1) Health check
    print("\n[1] HEALTH CHECK: GET /health")
    status, data = call("GET", "/health")
    print("HTTP:", status)
    print(pretty(data))
    time.sleep(DELAY_BETWEEN_CALLS)

    # 2) Register
    print("\n[2] REGISTER: POST /register")
    status, data = call("POST", "/register", body={
        "email": email,
        "password": password,
        "fullName": full_name,
        "dob": dob,
        "address": address
    })
    print("HTTP:", status)
    print(pretty(data))
    time.sleep(DELAY_BETWEEN_CALLS)

    # 3) Duplicate register (should fail with EMAIL_EXISTS)
    print("\n[3] DUPLICATE REGISTER (expect error): POST /register again")
    status, data = call("POST", "/register", body={
        "email": email,
        "password": password,
        "fullName": full_name,
        "dob": dob,
        "address": address
    })
    print("HTTP:", status)
    print(pretty(data))
    time.sleep(DELAY_BETWEEN_CALLS)

    # 4) Login success
    print("\n[4] LOGIN (expect ok): POST /login")
    status, data = call("POST", "/login", body={
        "email": email,
        "password": password
    })
    print("HTTP:", status)
    print(pretty(data))

    token = None
    if data.get("status") == "ok":
        token = data.get("data", {}).get("token")

    if not token:
        print("\nSTOP: Could not obtain token. Cannot test authenticated endpoints.")
        return
    time.sleep(DELAY_BETWEEN_CALLS)

    # 5) Login with wrong password (should fail)
    print("\n[5] LOGIN WRONG PASSWORD (expect error): POST /login")
    status, data = call("POST", "/login", body={
        "email": email,
        "password": "WrongPassword123"
    })
    print("HTTP:", status)
    print(pretty(data))
    time.sleep(DELAY_BETWEEN_CALLS)

    # 6) Get profile without token (should be 401)
    print("\n[6] GET PROFILE WITHOUT TOKEN (expect 401): GET /profile")
    status, data = call("GET", "/profile")
    print("HTTP:", status)
    print(pretty(data))
    time.sleep(DELAY_BETWEEN_CALLS)

    # 7) Get profile with token (should succeed)
    print("\n[7] GET PROFILE WITH TOKEN (expect ok): GET /profile")
    status, data = call("GET", "/profile", headers={
        "Authorization": f"Bearer {token}"
    })
    print("HTTP:", status)
    print(pretty(data))
    time.sleep(DELAY_BETWEEN_CALLS)

    # 8) Update profile (partial update)
    new_address = "200 Updated Road"
    print("\n[8] UPDATE PROFILE (expect ok): PATCH /profile")
    status, data = call("PATCH", "/profile", headers={
        "Authorization": f"Bearer {token}"
    }, body={
        "address": new_address
    })
    print("HTTP:", status)
    print(pretty(data))
    time.sleep(DELAY_BETWEEN_CALLS)

    # 9) Verify update by fetching profile again
    print("\n[9] VERIFY UPDATE (expect address changed): GET /profile")
    status, data = call("GET", "/profile", headers={
        "Authorization": f"Bearer {token}"
    })
    print("HTTP:", status)
    print(pretty(data))
    time.sleep(DELAY_BETWEEN_CALLS)

    print("\nDONE ✅ If steps [2], [4], [7], [8], [9] show status:'ok', the service works.")


if __name__ == "__main__":
    main()