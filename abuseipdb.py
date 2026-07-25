import requests

API_URL = "https://api.abuseipdb.com/api/v2/check"

API_KEY = "7b97f1f2590ee5f4238c52345a1967bcc228e6d80f1b1fee37efb17f0032b31f28f098e41a82f317"


def get_abuse_report(ip):

    headers = {
        "Key": API_KEY,
        "Accept": "application/json"
    }

    parameters = {
        "ipAddress": ip
    }

    response = requests.get(
        API_URL,
        headers=headers,
        params=parameters
    )

    return response.json()