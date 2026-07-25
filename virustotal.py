import requests

API_URL = "https://www.virustotal.com/api/v3/ip_addresses/"
API_KEY = "10e15a70a8a623f1b4ed98f2724adce43b613cde081e5a1b461f21034ed8363f"
def get_ip_report(ip):
    headers = {
        "x-apikey": API_KEY
    }

    response = requests.get(
        API_URL + ip,
        headers=headers
    )

    return response.json()