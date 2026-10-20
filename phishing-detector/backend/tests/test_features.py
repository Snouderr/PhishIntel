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


def test_model_features_are_extracted():
    # The saved model must only use columns extract_features() produces,
    # and never the list-membership features (label leakage).
    import joblib, os
    from feature_extraction import NON_MODEL_FEATURES
    here = os.path.dirname(__file__)
    bundle = joblib.load(os.path.join(here, "..", "model.pkl"))
    if isinstance(bundle, dict):
        cols = bundle["features"]
    else:
        cols = joblib.load(os.path.join(here, "..", "model_features.pkl"))
    assert set(cols) <= set(extract_features("https://example.com"))
    if isinstance(bundle, dict):
        assert not set(cols) & NON_MODEL_FEATURES


def test_typosquat_and_lookalike_features():
    f = extract_features("https://steamcommunlty-gift.ru/r")
    assert f["is_typosquat"] == 1
    assert extract_features("https://applied-science.edu")["is_typosquat"] == 0
    assert extract_features("http://paypa1-secure.com/login.php")["brand_edit_distance"] == 0
    assert extract_features("https://www.paypal.com/signin")["brand_edit_distance"] == 4
    assert extract_features("https://paypal.account-verify.xyz/")["brand_in_subdomain"] == 1
    assert extract_features("https://xn--pple-43d.com/")["is_punycode"] == 1


def test_structure_features():
    f = extract_features("https://myshop.weebly.com/a/b/login.php?next=http://x.com")
    assert f["is_free_hosting"] == 1 and f["path_depth"] == 3
    assert f["has_file_extension"] == 1 and f["has_embedded_url"] == 1
    assert extract_features("https://login.example.tk")["suspicious_tld"] == 1
    assert extract_features("https://qrco.de/abc")["is_shortened"] == 1
