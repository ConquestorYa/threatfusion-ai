import pytest


@pytest.fixture(autouse=True)
def _no_popular_site_download(monkeypatch):
    """Tests never download the public Tranco list."""
    from threatfusion import popular_domains

    def refuse(*args, **kwargs):
        raise RuntimeError("network access is disabled in tests")

    monkeypatch.setattr(popular_domains, "fetch_popular_domains", refuse)


@pytest.fixture(autouse=True)
def _no_registry_lookup(monkeypatch):
    """Tests never contact a real RDAP registry."""
    from threatfusion import domain_age

    def refuse(*args, **kwargs):
        raise RuntimeError("network access is disabled in tests")

    monkeypatch.setattr(domain_age, "_new_session", refuse)
    monkeypatch.setattr(domain_age, "_bootstrap_cache", None)


@pytest.fixture(autouse=True)
def _no_ip_owner_download(monkeypatch):
    """Tests never download the public IP owner table."""
    from threatfusion import ip_owners

    def refuse(*args, **kwargs):
        raise RuntimeError("network access is disabled in tests")

    monkeypatch.setattr(ip_owners, "fetch_ip_owners", refuse)


@pytest.fixture(autouse=True)
def _no_desktop_notifications(monkeypatch):
    """Tests never show a real desktop notification."""
    from threatfusion import notifications

    monkeypatch.setattr(notifications, "desktop_available", lambda: False)
