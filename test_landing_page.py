"""Static checks for the public Audit Chain project page."""

from pathlib import Path


PAGE = Path(__file__).resolve().parent / "web" / "index.html"


def test_landing_page_is_bilingual_static_and_uses_requested_color():
    page = PAGE.read_text(encoding="utf-8")

    assert '<html lang="en"' in page
    assert '--coral: #C2746E' in page
    assert 'data-language="en"' in page
    assert 'data-language="es"' in page
    assert 'fetch(' not in page


def test_landing_page_states_the_real_security_model():
    page = PAGE.read_text(encoding="utf-8")

    for claim in ('C · Rust · Java', 'SHA-256', 'Cascade forgery', 'INV-6', 'RFC 3161'):
        assert claim in page
