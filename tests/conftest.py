import pytest


@pytest.fixture(autouse=True)
def _no_popular_site_download(monkeypatch):
    """Tests never download the public Tranco list."""
    from threatfusion import popular_domains

    def refuse(*args, **kwargs):
        raise RuntimeError("network access is disabled in tests")

    monkeypatch.setattr(popular_domains, "fetch_popular_domains", refuse)
