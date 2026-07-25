from validator import is_valid_ip
from virustotal import get_ip_report
from abuseipdb import get_abuse_report
from ai_summary import generate_summary
print("=" * 40)
print("AI Threat Intelligence Investigation Assistant")
print("=" * 40)

print("\nEnter one or more IP addresses")
print("(One IP per line)")
print("Press ENTER twice when finished.\n")

ip_addresses = []

while True:
    ip = input()

    if ip == "":
        break

    ip_addresses.append(ip)

print("\nYou entered:")

for ip in ip_addresses:
    print(ip)
valid_ips = []

for ip in ip_addresses:
    if is_valid_ip(ip):
        valid_ips.append(ip)
    else:
        print(f"Invalid IP: {ip}")
print("\nValid IP addresses:")

for ip in valid_ips:
    print(ip)

print("\nChecking VirusTotal...")

for ip in valid_ips:

    report = get_ip_report(ip)
    abuse_report = get_abuse_report(ip)

    print("IP Address :", report["data"]["id"])
    print("Country    :", report["data"]["attributes"]["country"])
    print("ASN        :", report["data"]["attributes"]["asn"])
    print("Owner      :", report["data"]["attributes"]["as_owner"])

    stats = report["data"]["attributes"]["last_analysis_stats"]

    print("Malicious  :", stats["malicious"])
    print("Suspicious :", stats["suspicious"])
    print("Harmless   :", stats["harmless"])
    print("Undetected :", stats["undetected"])
    print("Reputation :", report["data"]["attributes"]["reputation"])

    if stats["malicious"] > 0:
        print("Verdict    : HIGH RISK - Investigate immediately.")

    elif stats["suspicious"] > 0:
        print("Verdict    : MEDIUM RISK - Suspicious detections found.")

    else:
        print("Verdict    : LOW RISK - No malicious or suspicious detections.")

    print("\nAbuseIPDB Report")
    abuse_data = abuse_report["data"]
    print("Confidence Score :", abuse_data["abuseConfidenceScore"])
    print("Country          :", abuse_data["countryCode"])
    print("ISP              :", abuse_data["isp"])
    print("Domain           :", abuse_data["domain"])
    print("Usage Type       :", abuse_data["usageType"])
    print("Whitelisted      :", abuse_data["isWhitelisted"])
    print("TOR Exit Node    :", abuse_data["isTor"])
    print("Total Reports    :", abuse_data["totalReports"])
    print("\n========================================")
    print("Overall Investigation Summary")
    print("========================================")

    if stats["malicious"] > 0:
        print("Overall Risk   : HIGH")
        print("Reason         : VirusTotal detected the IP as malicious.")
        print("Recommendation : Investigate immediately.")

    elif stats["suspicious"] > 0:
        print("Overall Risk   : MEDIUM")
        print("Reason         : VirusTotal detected suspicious activity.")
        print("Recommendation : Investigate further.")

    elif abuse_data["abuseConfidenceScore"] >= 50:
        print("Overall Risk   : MEDIUM")
        print("Reason         : AbuseIPDB reports a high abuse confidence score.")
        print("Recommendation : Review before allowing access.")

    else:
        print("Overall Risk   : LOW")
        print("Reason         : No malicious detections and low abuse confidence.")
        print("Recommendation : No immediate action required.")

    print("\nAI Investigation Summary")
    print(generate_summary(stats, abuse_data))