from promptshield import find_sensitive, shield_prompt


def test_email_redaction():
    assert shield_prompt("Email me at eduardo@example.com") == "Email me at [EMAIL]"


def test_phone_redaction():
    assert shield_prompt("Call +1 555 123 4567") == "Call [PHONE]"


def test_bearer_token_redaction():
    assert shield_prompt("Token: Bearer abc123456789") == "Token: [TOKEN]"


def test_api_key_redaction():
    assert shield_prompt("Key sk-test1234567890abcdef") == "Key [API_KEY]"


def test_github_token_redaction():
    assert shield_prompt("Token ghp_testtoken1234567890") == "Token [API_KEY]"


def test_sensitive_url_redaction():
    text = "Open https://example.com/reset?token=abc123"
    assert shield_prompt(text) == "Open [SENSITIVE_URL]"


def test_secret_assignment_redaction():
    assert shield_prompt("password=my-secret-value") == "[TOKEN]"


def test_custom_pattern_redaction():
    safe = shield_prompt("Customer ID: CUST-12345", {"customer_id": r"CUST-\d+"})
    assert safe == "Customer ID: [CUSTOM_CUSTOMER_ID]"


def test_find_sensitive_returns_type_start_end_value():
    matches = find_sensitive("My API key is sk-test123456789")

    assert matches == [
        {
            "type": "api_key",
            "value": "sk-test123456789",
            "start": 14,
            "end": 30,
        }
    ]


def test_no_sensitive_data_returns_unchanged_text():
    text = "Summarize this harmless sentence."
    assert shield_prompt(text) == text
    assert find_sensitive(text) == []


def test_multiple_matches_in_one_prompt():
    text = "Email eduardo@example.com with Bearer abc123456789 and call 555-123-4567"
    safe = shield_prompt(text)

    assert safe == "Email [EMAIL] with [TOKEN] and call [PHONE]"


def test_overlapping_matches_prefer_wider_match():
    text = "Visit https://example.com/reset?token=sk-test1234567890abcdef"
    safe = shield_prompt(text)

    assert safe == "Visit [SENSITIVE_URL]"


def test_repeated_values_do_not_break_redaction():
    text = "eduardo@example.com then eduardo@example.com"
    assert shield_prompt(text) == "[EMAIL] then [EMAIL]"
