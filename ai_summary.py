def generate_summary(stats, abuse_data):

    if stats["malicious"] > 0:
        return (
            "VirusTotal detected the IP as malicious. "
            "This IP should be investigated immediately and escalated if necessary."
        )

    elif stats["suspicious"] > 0:
        return (
            "VirusTotal reported suspicious detections. "
            "Further investigation is recommended before trusting this IP."
        )

    elif abuse_data["abuseConfidenceScore"] >= 50:
        return (
            "AbuseIPDB reports a high abuse confidence score. "
            "Review this IP carefully before allowing access."
        )

    else:
        return (
            "VirusTotal found no malicious or suspicious detections. "
            "AbuseIPDB reports a low abuse confidence score. "
            "Based on the available threat intelligence, this IP is currently considered low risk."
        )