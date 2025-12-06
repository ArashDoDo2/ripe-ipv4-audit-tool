import requests

def get_org_ipv4(org_id):
    url = f"https://rdap.db.ripe.net/entity/{org_id}"
    r = requests.get(url)

    if r.status_code != 200:
        print("Invalid ORG-ID")
        return []

    data = r.json()
    ipv4_list = []

    networks = data.get("networks", [])

    for net in networks:
        for block in net.get("cidr0_cidrs", []):
            if "v4prefix" in block:
                ipv4_list.append(f"{block['v4prefix']}/{block['length']}")

    return ipv4_list


# RUN
org_id = input("Enter ORG-ID: ").strip()
ipv4 = get_org_ipv4(org_id)

print("\n=== IPv4 CIDR RANGES ===\n")
if not ipv4:
    print("No IPv4 ranges found.")
else:
    for c in ipv4:
        print(c)
