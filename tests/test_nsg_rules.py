from azure_integration.nsg_rules import (
    analyze_nsg,
    opens_port_to_internet,
    port_matches
)


# Build a test rule (RDP open to the internet by default)
def rule(**overrides):
    base = {
        "name": "test-rule",
        "direction": "Inbound",
        "access": "Allow",
        "source_address_prefix": "*",
        "destination_port_range": "3389"
    }
    base.update(overrides)
    return base


# Single ports, ranges and *
def test_port_matches():
    assert port_matches("22", 22)
    assert port_matches("*", 22)
    assert port_matches("20-30", 22)
    assert not port_matches("80", 22)
    assert not port_matches("3000-4000", 22)


# RDP open to the internet is flagged
def test_rdp_open_to_internet():
    assert opens_port_to_internet(rule(), 3389)


# Internet service tag counts as the internet
def test_internet_service_tag():
    assert opens_port_to_internet(rule(source_address_prefix="Internet"), 3389)


# Deny rules are safe
def test_deny_rule_is_safe():
    assert not opens_port_to_internet(rule(access="Deny"), 3389)


# Outbound rules are safe
def test_outbound_rule_is_safe():
    assert not opens_port_to_internet(rule(direction="Outbound"), 3389)


# Private sources are safe
def test_private_source_is_safe():
    assert not opens_port_to_internet(rule(source_address_prefix="10.0.0.0/8"), 3389)


# Lists of ports and sources
def test_port_list_and_source_list():
    r = rule(
        source_address_prefix=None,
        source_address_prefixes=["10.0.0.0/8", "0.0.0.0/0"],
        destination_port_range=None,
        destination_port_ranges=["80", "443", "22"]
    )
    assert opens_port_to_internet(r, 22)
    assert not opens_port_to_internet(r, 3389)


# All ports open flags RDP and SSH
def test_all_ports_open():
    result = analyze_nsg("web-nsg", [rule(destination_port_range="*")])
    assert result["open_rdp"] and result["open_ssh"]


# No rules means nothing open
def test_no_rules():
    result = analyze_nsg("empty-nsg", [])
    assert not result["open_rdp"] and not result["open_ssh"]
