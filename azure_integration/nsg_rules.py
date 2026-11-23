INTERNET_SOURCES = ("*", "internet", "any", "0.0.0.0/0", "::/0")

RDP_PORT = 3389
SSH_PORT = 22


def as_list(single, multiple):

    values = []

    if single:
        values.append(single)

    if multiple:
        values.extend(multiple)

    return values


def port_matches(port_spec, port):

    port_spec = str(port_spec).strip()

    if port_spec == "*":
        return True

    if "-" in port_spec:
        start, end = port_spec.split("-", 1)
        return int(start) <= port <= int(end)

    return port_spec == str(port)


def opens_port_to_internet(rule, port):

    if str(rule.get("direction", "")).lower() != "inbound":
        return False

    if str(rule.get("access", "")).lower() != "allow":
        return False

    sources = as_list(
        rule.get("source_address_prefix"),
        rule.get("source_address_prefixes")
    )

    if not any(str(s).lower() in INTERNET_SOURCES for s in sources):
        return False

    ports = as_list(
        rule.get("destination_port_range"),
        rule.get("destination_port_ranges")
    )

    return any(port_matches(p, port) for p in ports)


def analyze_nsg(name, rules):

    return {
        "name": name,
        "open_rdp": any(opens_port_to_internet(r, RDP_PORT) for r in rules),
        "open_ssh": any(opens_port_to_internet(r, SSH_PORT) for r in rules),
        "rule_count": len(rules)
    }
