# Sources that mean anyone on the internet
INTERNET_SOURCES = ("*", "internet", "any", "0.0.0.0/0", "::/0")

# Ports to check
RDP_PORT = 3389
SSH_PORT = 22


# Combine a single value and a list into one list
def as_list(single, multiple):

    values = []

    if single:
        values.append(single)

    if multiple:
        values.extend(multiple)

    return values


# Check if a port is covered by a rule's port setting
def port_matches(port_spec, port):

    port_spec = str(port_spec).strip()

    # Any port
    if port_spec == "*":
        return True

    # Port range, e.g. 20-30
    if "-" in port_spec:
        start, end = port_spec.split("-", 1)
        return int(start) <= port <= int(end)

    # Single port
    return port_spec == str(port)


# Check if a rule allows a port in from the internet
def opens_port_to_internet(rule, port):

    # Only inbound rules
    if str(rule.get("direction", "")).lower() != "inbound":
        return False

    # Only allow rules
    if str(rule.get("access", "")).lower() != "allow":
        return False

    # Check the source is the internet
    sources = as_list(
        rule.get("source_address_prefix"),
        rule.get("source_address_prefixes")
    )

    if not any(str(s).lower() in INTERNET_SOURCES for s in sources):
        return False

    # Check the port is covered
    ports = as_list(
        rule.get("destination_port_range"),
        rule.get("destination_port_ranges")
    )

    return any(port_matches(p, port) for p in ports)


# Summarise an NSG's open RDP and SSH access
def analyze_nsg(name, rules):

    return {
        "name": name,
        "open_rdp": any(opens_port_to_internet(r, RDP_PORT) for r in rules),
        "open_ssh": any(opens_port_to_internet(r, SSH_PORT) for r in rules),
        "rule_count": len(rules)
    }
