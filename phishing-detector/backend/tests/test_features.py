from feature_extraction import _split_domain, extract_features, get_full_domain


def test_split_domain_simple():
    assert _split_domain("www.example.com") == ("www", "example", "com")


def test_split_domain_multi_part_suffix():
    assert _split_domain("login.example.co.uk") == ("login", "example", "co.uk")


def test_bank_in_is_suffix_not_apex():
    # icici.bank.in and hdfc.bank.in are different organizations
    assert get_full_domain("https://netbanking.icici.bank.in/") == "icici.bank.in"


def test_get_full_domain_without_scheme():
    assert get_full_domain("foo.github.io/page") == "github.io"


def test_www_does_not_count_as_subdomain():
    assert extract_features("https://www.example.com")["num_subdomains"] == 0
    assert extract_features("https://login.verify.example.com")["num_subdomains"] == 2


def test_ip_address_detected():
    f = extract_features("http://192.168.1.1/banking/confirm")
    assert f["has_ip_address"] == 1
    assert f["uses_https"] == 0


def test_root_slash_is_not_a_path():
    assert extract_features("https://example.com/")["path_length"] == 0


def test_suspicious_word_and_query_params():
    f = extract_features("http://paypal-secure-login.tk/verify/account?id=1&x=2")
    assert f["has_suspicious_word"] == 1
    assert f["num_query_params"] == 2


def test_restricted_tld():
    assert extract_features("https://icici.bank.in")["is_restricted_tld"] == 1
    assert extract_features("https://example.co.in")["is_restricted_tld"] == 0


def test_shortener():
    assert extract_features("https://bit.ly/abc")["is_shortened"] == 1


def test_trusted_domain_lookup():
    assert extract_features("https://www.google.com")["is_trusted_domain"] == 1


def test_feature_set_is_stable():
    # The saved model depends on this exact column set.
    import joblib, os
    cols = joblib.load(os.path.join(os.path.dirname(__file__), "..", "model_features.pkl"))
    assert set(extract_features("https://example.com")) == set(cols)
