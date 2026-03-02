import requests
import json

BASE_URL = "http://127.0.0.1:8000"

def test_registration(email, phone):
    print(f"\nTesting: {email} / {phone}")
    payload = {
        "email": email,
        "phone": phone
    }
    try:
        response = requests.post(f"{BASE_URL}/check_registration", json=payload)
        if response.status_code == 200:
            data = response.json()
            print(f"Status: {data['status']}")
            print(f"Spam Score: {data['spam_score']}")
            print(f"Notes: {data['detection_notes']}")
        else:
            print(f"Error ({response.status_code}): {response.text}")
    except Exception as e:
        print(f"Request failed: {e}")

if __name__ == "__main__":
    # Test a likely legitimate email
    test_registration("john.doe.testing@gmail.com", "+12345678901")
    
    # Test a likely abusive email (random junk)
    test_registration("a1b2c3d4e5f6g7h8@tempmail.com", "+98765432109")
    
    # Test a keyword based spam
    test_registration("free.promo.spam@example.com", "+11223344556")
