"""Runnable checks for subsift. `python3 -m pytest` or `python3 tests/test_subsift.py`."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from subsift import classify, subdomain_labels  # noqa: E402


def test_noise_dropped():
    for junk in ["pr-1234.preview.example.com",
                 "2871-fix-404-uncover.ci0.dev.lieferando.de",
                 "a1b2c3d4e5f6.example.com",
                 "1zw.courses.pr.dev.www.stamp.frontend.office.prod.clops.pyszne.pl"]:
        assert classify(junk).noise, f"expected noise: {junk}"


def test_cctld_not_mistaken_for_mail():
    # .mx must not be read as mail; content is not a category
    h = classify("admin.content.nu.com.mx")
    assert "mail" not in h.categories
    assert "admin" in h.categories


def test_subdomain_labels_strip_apex():
    assert subdomain_labels("a.b.example.com".split(".")) == ["a", "b"]
    assert subdomain_labels("gitlab.api.10bis.co.il".split(".")) == ["gitlab", "api"]
    assert subdomain_labels("nubank.com.br".split(".")) == []


def test_high_value_scoring():
    hi = classify("admin.api-courier.skipthedishes.com")
    lo = classify("static.assets.example.com")
    assert hi.score > lo.score
    assert "admin" in hi.categories and "api" in hi.categories
    assert "storage" in lo.categories


def test_env_detection():
    assert classify("app.dev.playable.com").env == "dev"
    assert classify("api.staging.example.com").env == "staging"
    assert classify("www.example.com").env == "prod"


def test_real_juicy_host_surfaces():
    h = classify("docker-registry.dev.pyszne.pl")
    assert h.env == "dev"
    assert "cicd" in h.categories or "infra" in h.categories
    assert h.score >= 5


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} checks passed")
