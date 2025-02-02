CARRIER_GATEWAYS = {
    "AT&T": "txt.att.net",
    "Verizon": "vtext.com",
    "T-Mobile": "tmomail.net",
    # Add more carriers here as needed
}

def get_carrier_gateway(carrier: str) -> str:
    """
    Returns the email gateway for the given carrier.
    Defaults to AT&T if the carrier is not found.
    """
    return CARRIER_GATEWAYS.get(carrier, "txt.att.net")
