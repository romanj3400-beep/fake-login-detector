import ipaddress
from urllib.parse import urlparse

def get_url():
    url = input("Enter a URL to analyze: ").strip()

    if not url:
        print("Error: Please enter a URL.")
        exit()

    if " " in url:
        print("Error: URL contains spaces.")
        exit()

    return url


Url_shorteners = ["bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "is.gd", "buff.ly", "adf.ly", "bit.do", "cutt.ly"]

known_brands = ["paypal.com", "google.com", "facebook.com", "amazon.com", "apple.com", "microsoft.com", "bankofamerica.com", "chase.com", "wellsfargo.com"]

suspicious_keywords = ["login", "secure", "update", "verify", "account", "banking", "confirm", "password", "signin"]


def analyze_url(url):

    warnings = []

    risk_factors = []

    suspicious_score = 0

    print("original URL:", url)

    if not url.startswith(("http://", "https://")):
        print("Protocol missing, assuming HTTPS for analysis")
        url = "https://" + url

    if url.startswith("https://"):
        print("HTTPS Detected")
    else:
        print("Not HTTPS")

    if len(url) > 75:
        print("URL is unusually long")
        suspicious_score += 1
        risk_factors.append("URL length exceeds 75 characters")
        warnings.append("URL is unusually long")
    else:
        print("URL length is acceptable")

    if "@" in url:
        print("URL contains '@' symbol, which is suspicious")
        suspicious_score += 1
        risk_factors.append("URL contains '@' symbol, which can be used to obscure the true destination")
        warnings.append("URL contains '@' symbol")
    else:
        print("No '@' symbol found in the URL")

    for keyword in suspicious_keywords:
        if keyword in url.lower():
            print(f"Informational keyword detected: {keyword}")
            warnings.append(f"Informational keyword: {keyword}")

    parsed_url = urlparse(url)
    hostname = parsed_url.hostname

    if not hostname:
        print("Error: invalid URL, hostname could not be extracted")
        exit()

    if hostname.startswith(".") or hostname.endswith("."):
        print("Error: hostname cannot start or end with a dot")
        exit()

    if "." not in hostname:
        print("Warning: hostname may be incomplete or invalid")
        warnings.append("Hostname may be incomplete or invalid")

    if ".." in hostname:
        print("Warning: hostname contains consecutive dots")
        suspicious_score += 1
        risk_factors.append("Hostname contains consecutive dots, which can be used to create deceptive URLs")
        warnings.append("Hostname contains consecutive dots")

    try:
        port = parsed_url.port

        if port is not None and port not in [80, 443]:
            print(f"Suspicious port detected: {port}")
            warnings.append(f"Suspicious port: {port}")
        else:
            print("No suspicious port detected")

    except ValueError:
        print("Error: Invalid port number")
        exit()

    print("Hostname:", hostname)

    try:
        ip = ipaddress.ip_address(hostname)
        print("Hostname is an IP address:", ip)
        suspicious_score += 1
        risk_factors.append("Hostname is an IP address, which can make the website's identity harder to verify")
        warnings.append(
            "Hostname is an IP address, which can make "
            "the website's identity harder to verify"
        )
    except ValueError:
        print("Hostname appears to be a domain name:", hostname)

    for shortener in Url_shorteners:
        if hostname.lower() == shortener:
            print(f"Warning: URL uses a known URL shortener: {shortener}")
            warnings.append(f"URL uses a known URL shortener: {shortener}")
            break
    else:
        print("Hostname is not a known URL shortener")

    
    for brand in known_brands:
        hostname_lower = hostname.lower()

        if brand in hostname_lower:
            if (
                hostname_lower == brand
                or hostname_lower.endswith("." + brand)
            ):
                print(f"Official brand domain match: {brand}")
            else:
                print(
                    f"Suspicious domain detected: {hostname} "
                    f"contains known brand {brand} but is not "
                    "the official domain"
                )
                suspicious_score += 1
                risk_factors.append(f"hostname may impersonate known brand {brand}")
                warnings.append(
                    f"Suspicious domain: {hostname} contains {brand}, "
                    "but may not be the official brand domain. "
                    "This could indicate impersonation or phishing."
                )
            break
    else:
        print("No known brand detected in the hostname")


    return {"url": url, "hostname": hostname, "score": suspicious_score, "warnings": warnings, "risk_factors": risk_factors}
def main():
    url = get_url()
    print("original URL:", url)

    try: 
        result = analyze_url(url)
    except ValueError as error:
        print("Error during URL analysis:", error)
        exit()

    suspicious_score = result["score"]
    warnings = result["warnings"]
    risk_factors = result["risk_factors"]

    print("Suspicious Score:", suspicious_score)

    print("\nRisk Factors:")

    if len(risk_factors) == 0:
        print("No scored risk factors detected.")
    else:
        for factor in risk_factors:
            print("-", factor)

    print("Note: This score is based on basic URL indicators,")
    print("not a verified probability that a website is phishing.")

    if suspicious_score == 0:
        print("No suspicious indicators were scored.")
        print("This does not guarantee that the URL is safe.")
    elif suspicious_score <= 2:
        print("Some suspicious indicators were detected.")
        print("Review the warnings before visiting the site.")
    else:
        print("Multiple suspicious indicators were detected.")
        print("Avoid visiting the site until it has been further checked.")

    print("\nWarnings:")
    print("Total warnings:", len(warnings))

    if len(warnings) == 0:
        print("No warnings detected.")
    else:
        for warning in warnings:
            print("-", warning)


if __name__ == "__main__":
    main()


