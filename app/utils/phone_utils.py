import phonenumbers

def validate_phone_number(phoneNumber: str, region: str = "US") -> bool:
    """
    Validates the given phone number using the specified region code.
    """
    try:
        parsed_number = phonenumbers.parse(phoneNumber, region)
        return phonenumbers.is_valid_number(parsed_number)
    except phonenumbers.NumberParseException:
        return False
