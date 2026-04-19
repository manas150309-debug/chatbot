import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
OUTPUT_PATH = BASE_DIR / "data" / "company_threat_profiles_kb.json"


PROFILES = [
    {
        "rank": 2,
        "company": "Amazon",
        "domain": "amazon.com",
        "security_level": "A",
        "domain_based_threats": [
            {"threat": "Credential stuffing attacks", "cve_id": "CVE-2026-0001"},
            {"threat": "Distributed Denial of Service (DDoS)", "cve_id": "CVE-2026-0002"},
            {"threat": "API abuse and bot traffic", "cve_id": "CVE-2026-0003"},
            {"threat": "Cloud misconfiguration vulnerabilities", "cve_id": "CVE-2026-0004"},
        ],
        "company_specific_threats": [
            {"threat": "Fake seller account fraud", "cve_id": "CVE-2026-0005"},
            {"threat": "AWS misconfiguration leading to data leaks", "cve_id": "CVE-2026-0006"},
            {"threat": "Phishing targeting Amazon customers", "cve_id": "CVE-2026-0007"},
            {"threat": "Supply chain manipulation in marketplace", "cve_id": "CVE-2026-0008"},
        ],
    },
    {
        "rank": 3,
        "company": "UnitedHealth Group",
        "domain": "unitedhealthgroup.com",
        "security_level": "A",
        "domain_based_threats": [
            {"threat": "Healthcare data breaches", "cve_id": "CVE-2026-0009"},
            {"threat": "Ransomware attacks", "cve_id": "CVE-2026-0010"},
            {"threat": "Insider threats", "cve_id": "CVE-2026-0011"},
            {"threat": "API exposure vulnerabilities", "cve_id": "CVE-2026-0012"},
        ],
        "company_specific_threats": [
            {"threat": "Patient record theft", "cve_id": "CVE-2026-0013"},
            {"threat": "Insurance fraud via compromised accounts", "cve_id": "CVE-2026-0014"},
            {"threat": "Targeted ransomware on hospital systems", "cve_id": "CVE-2026-0015"},
            {"threat": "Third-party vendor breaches", "cve_id": "CVE-2026-0016"},
        ],
    },
    {
        "rank": 4,
        "company": "Apple",
        "domain": "apple.com",
        "security_level": "A",
        "domain_based_threats": [
            {"threat": "Zero-day exploits", "cve_id": "CVE-2026-0017"},
            {"threat": "Supply chain attacks", "cve_id": "CVE-2026-0018"},
            {"threat": "Device-level malware", "cve_id": "CVE-2026-0019"},
            {"threat": "Phishing campaigns", "cve_id": "CVE-2026-0020"},
        ],
        "company_specific_threats": [
            {"threat": "iCloud account hijacking", "cve_id": "CVE-2026-0021"},
            {"threat": "App Store malware injection attempts", "cve_id": "CVE-2026-0022"},
            {"threat": "Jailbreak exploit abuse", "cve_id": "CVE-2026-0023"},
            {"threat": "Targeted attacks on Apple ID ecosystem", "cve_id": "CVE-2026-0024"},
        ],
    },
    {
        "rank": 7,
        "company": "Alphabet",
        "domain": "abc.xyz",
        "security_level": "A",
        "domain_based_threats": [
            {"threat": "Cloud service misconfigurations", "cve_id": "CVE-2026-0025"},
            {"threat": "API abuse and data scraping", "cve_id": "CVE-2026-0026"},
            {"threat": "Account takeover attacks", "cve_id": "CVE-2026-0027"},
            {"threat": "Ad fraud and botnets", "cve_id": "CVE-2026-0028"},
        ],
        "company_specific_threats": [
            {"threat": "Gmail phishing campaigns", "cve_id": "CVE-2026-0029"},
            {"threat": "Google Cloud data exposure", "cve_id": "CVE-2026-0030"},
            {"threat": "YouTube content manipulation bots", "cve_id": "CVE-2026-0031"},
            {"threat": "OAuth token hijacking", "cve_id": "CVE-2026-0032"},
        ],
    },
    {
        "rank": 11,
        "company": "JPMorgan Chase",
        "domain": "jpmorganchase.com",
        "security_level": "A",
        "domain_based_threats": [
            {"threat": "Financial fraud attacks", "cve_id": "CVE-2026-0033"},
            {"threat": "Phishing and credential theft", "cve_id": "CVE-2026-0034"},
            {"threat": "Insider threats", "cve_id": "CVE-2026-0035"},
            {"threat": "DDoS on banking services", "cve_id": "CVE-2026-0036"},
        ],
        "company_specific_threats": [
            {"threat": "Unauthorized wire transfers", "cve_id": "CVE-2026-0037"},
            {"threat": "Mobile banking malware", "cve_id": "CVE-2026-0038"},
            {"threat": "SWIFT network exploitation attempts", "cve_id": "CVE-2026-0039"},
            {"threat": "High-value account targeting", "cve_id": "CVE-2026-0040"},
        ],
    },
    {
        "rank": 14,
        "company": "Microsoft",
        "domain": "microsoft.com",
        "security_level": "A",
        "domain_based_threats": [
            {"threat": "Zero-day vulnerabilities", "cve_id": "CVE-2026-0049"},
            {"threat": "Cloud misconfigurations", "cve_id": "CVE-2026-0050"},
            {"threat": "Credential theft attacks", "cve_id": "CVE-2026-0051"},
            {"threat": "Ransomware attacks", "cve_id": "CVE-2026-0052"},
        ],
        "company_specific_threats": [
            {"threat": "Azure data exposure", "cve_id": "CVE-2026-0053"},
            {"threat": "Office 365 phishing attacks", "cve_id": "CVE-2026-0054"},
            {"threat": "Windows exploit targeting", "cve_id": "CVE-2026-0055"},
            {"threat": "Teams spoofing attacks", "cve_id": "CVE-2026-0056"},
        ],
    },
    {
        "rank": 17,
        "company": "Bank of America",
        "domain": "bankofamerica.com",
        "security_level": "A",
        "domain_based_threats": [
            {"threat": "Banking fraud", "cve_id": "CVE-2026-0057"},
            {"threat": "Credential stuffing", "cve_id": "CVE-2026-0058"},
            {"threat": "Phishing campaigns", "cve_id": "CVE-2026-0059"},
            {"threat": "DDoS attacks", "cve_id": "CVE-2026-0060"},
        ],
        "company_specific_threats": [
            {"threat": "Account takeover fraud", "cve_id": "CVE-2026-0061"},
            {"threat": "ATM malware attacks", "cve_id": "CVE-2026-0062"},
            {"threat": "Mobile banking trojans", "cve_id": "CVE-2026-0063"},
            {"threat": "Wire transfer scams", "cve_id": "CVE-2026-0064"},
        ],
    },
    {
        "rank": 22,
        "company": "Meta Platforms",
        "domain": "atmeta.com",
        "security_level": "A",
        "domain_based_threats": [
            {"threat": "Social engineering attacks", "cve_id": "CVE-2026-0081"},
            {"threat": "Account hijacking", "cve_id": "CVE-2026-0082"},
            {"threat": "API abuse and bot activity", "cve_id": "CVE-2026-0083"},
            {"threat": "Data scraping attacks", "cve_id": "CVE-2026-0084"},
        ],
        "company_specific_threats": [
            {"threat": "Facebook account takeovers", "cve_id": "CVE-2026-0085"},
            {"threat": "Instagram phishing scams", "cve_id": "CVE-2026-0086"},
            {"threat": "Ad platform abuse", "cve_id": "CVE-2026-0087"},
            {"threat": "Fake profile bot networks", "cve_id": "CVE-2026-0088"},
        ],
    },
    {
        "rank": 31,
        "company": "Nvidia",
        "domain": "nvidia.com",
        "security_level": "A",
        "domain_based_threats": [
            {"threat": "Supply chain attacks", "cve_id": "CVE-2026-0105"},
            {"threat": "Firmware vulnerabilities", "cve_id": "CVE-2026-0106"},
            {"threat": "GPU driver exploits", "cve_id": "CVE-2026-0107"},
            {"threat": "Intellectual property theft", "cve_id": "CVE-2026-0108"},
        ],
        "company_specific_threats": [
            {"threat": "AI model theft", "cve_id": "CVE-2026-0109"},
            {"threat": "CUDA exploit vulnerabilities", "cve_id": "CVE-2026-0110"},
            {"threat": "Datacenter GPU attacks", "cve_id": "CVE-2026-0111"},
            {"threat": "Driver-level privilege escalation", "cve_id": "CVE-2026-0112"},
        ],
    },
    {
        "rank": 35,
        "company": "Comcast",
        "domain": "comcastcorporation.com",
        "security_level": "A",
        "domain_based_threats": [
            {"threat": "Network attacks", "cve_id": "CVE-2026-0129"},
            {"threat": "DDoS attacks", "cve_id": "CVE-2026-0130"},
            {"threat": "Data interception", "cve_id": "CVE-2026-0131"},
            {"threat": "Botnet exploitation", "cve_id": "CVE-2026-0132"},
        ],
        "company_specific_threats": [
            {"threat": "Cable network breaches", "cve_id": "CVE-2026-0133"},
            {"threat": "Customer data leaks", "cve_id": "CVE-2026-0134"},
            {"threat": "Router firmware exploits", "cve_id": "CVE-2026-0135"},
            {"threat": "Streaming service piracy attacks", "cve_id": "CVE-2026-0136"},
        ],
    },
    {
        "rank": 37,
        "company": "AT&T",
        "domain": "att.com",
        "security_level": "A",
        "domain_based_threats": [
            {"threat": "Telecom network attacks", "cve_id": "CVE-2026-0137"},
            {"threat": "SIM swap fraud", "cve_id": "CVE-2026-0138"},
            {"threat": "DDoS attacks", "cve_id": "CVE-2026-0139"},
            {"threat": "Data interception", "cve_id": "CVE-2026-0140"},
        ],
        "company_specific_threats": [
            {"threat": "Customer data breaches", "cve_id": "CVE-2026-0141"},
            {"threat": "5G infrastructure exploits", "cve_id": "CVE-2026-0142"},
            {"threat": "SIM hijacking attacks", "cve_id": "CVE-2026-0143"},
            {"threat": "Enterprise connectivity disruption", "cve_id": "CVE-2026-0144"},
        ],
    },
    {
        "rank": 43,
        "company": "Tesla",
        "domain": "tesla.com",
        "security_level": "A",
        "domain_based_threats": [
            {"threat": "IoT vulnerabilities", "cve_id": "CVE-2026-0161"},
            {"threat": "Firmware exploits", "cve_id": "CVE-2026-0162"},
            {"threat": "Remote access attacks", "cve_id": "CVE-2026-0163"},
            {"threat": "Supply chain attacks", "cve_id": "CVE-2026-0164"},
        ],
        "company_specific_threats": [
            {"threat": "Vehicle remote control exploits", "cve_id": "CVE-2026-0165"},
            {"threat": "Autopilot system vulnerabilities", "cve_id": "CVE-2026-0166"},
            {"threat": "Charging network attacks", "cve_id": "CVE-2026-0167"},
            {"threat": "Tesla account takeover", "cve_id": "CVE-2026-0168"},
        ],
    },
    {
        "rank": 48,
        "company": "Johnson & Johnson",
        "domain": "jnj.com",
        "security_level": "A",
        "domain_based_threats": [
            {"threat": "Healthcare data breaches", "cve_id": "CVE-2026-0177"},
            {"threat": "Ransomware attacks", "cve_id": "CVE-2026-0178"},
            {"threat": "Supply chain attacks", "cve_id": "CVE-2026-0179"},
            {"threat": "Insider threats", "cve_id": "CVE-2026-0180"},
        ],
        "company_specific_threats": [
            {"threat": "Medical device vulnerabilities", "cve_id": "CVE-2026-0181"},
            {"threat": "Drug research data theft", "cve_id": "CVE-2026-0182"},
            {"threat": "Clinical trial data breaches", "cve_id": "CVE-2026-0183"},
            {"threat": "Pharmaceutical supply chain attacks", "cve_id": "CVE-2026-0184"},
        ],
    },
    {
        "rank": 58,
        "company": "American Express",
        "domain": "americanexpress.com",
        "security_level": "A",
        "domain_based_threats": [
            {"threat": "Payment fraud", "cve_id": "CVE-2026-0193"},
            {"threat": "Phishing attacks", "cve_id": "CVE-2026-0194"},
            {"threat": "Credential stuffing", "cve_id": "CVE-2026-0195"},
            {"threat": "API vulnerabilities", "cve_id": "CVE-2026-0196"},
        ],
        "company_specific_threats": [
            {"threat": "Credit card fraud schemes", "cve_id": "CVE-2026-0197"},
            {"threat": "Transaction data breaches", "cve_id": "CVE-2026-0198"},
            {"threat": "Account takeover attacks", "cve_id": "CVE-2026-0199"},
            {"threat": "Merchant system compromise", "cve_id": "CVE-2026-0200"},
        ],
    },
    {
        "rank": 73,
        "company": "Oracle",
        "domain": "oracle.com",
        "security_level": "A",
        "domain_based_threats": [
            {"threat": "Database vulnerabilities", "cve_id": "CVE-2026-0233"},
            {"threat": "Cloud misconfigurations", "cve_id": "CVE-2026-0234"},
            {"threat": "Zero-day exploits", "cve_id": "CVE-2026-0235"},
            {"threat": "API security flaws", "cve_id": "CVE-2026-0236"},
        ],
        "company_specific_threats": [
            {"threat": "Oracle DB exploit attempts", "cve_id": "CVE-2026-0237"},
            {"threat": "Enterprise cloud data leaks", "cve_id": "CVE-2026-0238"},
            {"threat": "ERP system compromise", "cve_id": "CVE-2026-0239"},
            {"threat": "Privilege escalation in DB systems", "cve_id": "CVE-2026-0240"},
        ],
    },
    {
        "rank": 106,
        "company": "Netflix",
        "domain": "netflix.com",
        "security_level": "A",
        "domain_based_threats": [
            {"threat": "Account takeover attacks", "cve_id": "CVE-2026-0345"},
            {"threat": "Credential stuffing", "cve_id": "CVE-2026-0346"},
            {"threat": "DDoS attacks", "cve_id": "CVE-2026-0347"},
            {"threat": "Content piracy", "cve_id": "CVE-2026-0348"},
        ],
        "company_specific_threats": [
            {"threat": "Account sharing abuse exploitation", "cve_id": "CVE-2026-0349"},
            {"threat": "Streaming infrastructure attacks", "cve_id": "CVE-2026-0350"},
            {"threat": "Recommendation algorithm manipulation", "cve_id": "CVE-2026-0351"},
            {"threat": "User data leakage", "cve_id": "CVE-2026-0352"},
        ],
    },
    {
        "rank": 130,
        "company": "Cisco Systems",
        "domain": "cisco.com",
        "security_level": "A",
        "domain_based_threats": [
            {"threat": "Network vulnerabilities", "cve_id": "CVE-2026-0449"},
            {"threat": "Firmware exploits", "cve_id": "CVE-2026-0450"},
            {"threat": "Zero-day vulnerabilities", "cve_id": "CVE-2026-0451"},
            {"threat": "DDoS attacks", "cve_id": "CVE-2026-0452"},
        ],
        "company_specific_threats": [
            {"threat": "Router firmware vulnerabilities", "cve_id": "CVE-2026-0453"},
            {"threat": "Enterprise network breaches", "cve_id": "CVE-2026-0454"},
            {"threat": "Switch exploitation attacks", "cve_id": "CVE-2026-0455"},
            {"threat": "Network backdoor insertion", "cve_id": "CVE-2026-0456"},
        ],
    },
    {
        "rank": 131,
        "company": "Salesforce",
        "domain": "salesforce.com",
        "security_level": "A",
        "domain_based_threats": [
            {"threat": "Cloud misconfiguration", "cve_id": "CVE-2026-0457"},
            {"threat": "API vulnerabilities", "cve_id": "CVE-2026-0458"},
            {"threat": "Credential theft", "cve_id": "CVE-2026-0459"},
            {"threat": "Data breaches", "cve_id": "CVE-2026-0460"},
        ],
        "company_specific_threats": [
            {"threat": "CRM data leakage", "cve_id": "CVE-2026-0461"},
            {"threat": "Unauthorized access to client data", "cve_id": "CVE-2026-0462"},
            {"threat": "API abuse attacks", "cve_id": "CVE-2026-0463"},
            {"threat": "Third-party integration vulnerabilities", "cve_id": "CVE-2026-0464"},
        ],
    },
    {
        "rank": 132,
        "company": "Adobe",
        "domain": "adobe.com",
        "security_level": "A",
        "domain_based_threats": [
            {"threat": "Software vulnerabilities", "cve_id": "CVE-2026-0465"},
            {"threat": "Zero-day exploits", "cve_id": "CVE-2026-0466"},
            {"threat": "Phishing attacks", "cve_id": "CVE-2026-0467"},
            {"threat": "Credential theft", "cve_id": "CVE-2026-0468"},
        ],
        "company_specific_threats": [
            {"threat": "PDF exploit vulnerabilities", "cve_id": "CVE-2026-0469"},
            {"threat": "Creative Cloud account hijacking", "cve_id": "CVE-2026-0470"},
            {"threat": "Software license abuse", "cve_id": "CVE-2026-0471"},
            {"threat": "Malicious plugin injection", "cve_id": "CVE-2026-0472"},
        ],
    },
    {
        "rank": 134,
        "company": "Airbnb",
        "domain": "airbnb.com",
        "security_level": "A",
        "domain_based_threats": [
            {"threat": "Account takeover attacks", "cve_id": "CVE-2026-0481"},
            {"threat": "Phishing attacks", "cve_id": "CVE-2026-0482"},
            {"threat": "Payment fraud", "cve_id": "CVE-2026-0483"},
            {"threat": "API abuse", "cve_id": "CVE-2026-0484"},
        ],
        "company_specific_threats": [
            {"threat": "Fake listing scams", "cve_id": "CVE-2026-0485"},
            {"threat": "Host account hijacking", "cve_id": "CVE-2026-0486"},
            {"threat": "Guest identity fraud", "cve_id": "CVE-2026-0487"},
            {"threat": "Unauthorized payment transactions", "cve_id": "CVE-2026-0488"},
        ],
    },
    {
        "rank": 135,
        "company": "Uber Technologies",
        "domain": "uber.com",
        "security_level": "A",
        "domain_based_threats": [
            {"threat": "Account takeover attacks", "cve_id": "CVE-2026-0489"},
            {"threat": "API abuse", "cve_id": "CVE-2026-0490"},
            {"threat": "Payment fraud", "cve_id": "CVE-2026-0491"},
            {"threat": "Location data exposure", "cve_id": "CVE-2026-0492"},
        ],
        "company_specific_threats": [
            {"threat": "Driver account hijacking", "cve_id": "CVE-2026-0493"},
            {"threat": "Ride spoofing attacks", "cve_id": "CVE-2026-0494"},
            {"threat": "Fare manipulation fraud", "cve_id": "CVE-2026-0495"},
            {"threat": "User location tracking abuse", "cve_id": "CVE-2026-0496"},
        ],
    },
    {
        "rank": 136,
        "company": "Palo Alto Networks",
        "domain": "paloaltonetworks.com",
        "security_level": "A",
        "domain_based_threats": [
            {"threat": "Zero-day vulnerabilities", "cve_id": "CVE-2026-0497"},
            {"threat": "Network attacks", "cve_id": "CVE-2026-0498"},
            {"threat": "Advanced persistent threats", "cve_id": "CVE-2026-0499"},
            {"threat": "Cloud security flaws", "cve_id": "CVE-2026-0500"},
        ],
        "company_specific_threats": [
            {"threat": "Firewall bypass exploits", "cve_id": "CVE-2026-0501"},
            {"threat": "Security platform vulnerabilities", "cve_id": "CVE-2026-0502"},
            {"threat": "Threat intelligence manipulation", "cve_id": "CVE-2026-0503"},
            {"threat": "Zero-day exploit targeting", "cve_id": "CVE-2026-0504"},
        ],
    },
]


def build_document(profile):
    domain_lines = [
        f"- {item['threat']} (Local threat ID: {item['cve_id']})"
        for item in profile["domain_based_threats"]
    ]
    company_lines = [
        f"- {item['threat']} (Local threat ID: {item['cve_id']})"
        for item in profile["company_specific_threats"]
    ]
    return {
        "doc_key": f"company-threat-{profile['company'].lower().replace('&', 'and').replace(' ', '-').replace('.', '')}",
        "title": profile["company"],
        "category": "company-threat-profile",
        "source_url": f"https://{profile['domain']}",
        "content": "\n".join(
            [
                f"Company: {profile['company']}",
                f"Rank: {profile['rank']}",
                f"Domain: {profile['domain']}",
                f"Security level: {profile['security_level']}",
                "Dataset note: The CVE-style IDs below are local threat-profile labels from the provided dataset, not official public CVE records.",
                "",
                "Domain-based threats:",
                *domain_lines,
                "",
                "Company-specific threats:",
                *company_lines,
            ]
        ),
    }


def main():
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {"documents": [build_document(profile) for profile in PROFILES]}
    OUTPUT_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"Wrote {len(payload['documents'])} company threat profiles to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
