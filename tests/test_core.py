from fingerprint_core import collect_asset_urls, extract_trackers, looks_like_html, normalize_html_text


def test_extract_trackers():
    html = """
    <script>
      var ua = 'UA-12345678-1';
      var ga4 = 'G-1A2B3C4D';
      var gtm = 'GTM-ABCDE1';
      fbq('init','1234567890');
    </script>
    """
    ga_ids, ga4_ids, gtm_ids, fb_ids = extract_trackers(html)
    assert ga_ids == ["UA-12345678-1"]
    assert ga4_ids == ["G-1A2B3C4D"]
    assert gtm_ids == ["GTM-ABCDE1"]
    assert fb_ids == ["1234567890"]


def test_collect_asset_urls():
    html = """
    <link rel="stylesheet" href="/static/site.css" />
    <script src="/static/app.js"></script>
    <img src="/static/logo.png" />
    <iframe src="https://example.com/embed"></iframe>
    <script src="data:ignore"></script>
    """
    urls = collect_asset_urls(html, "http://localhost:8000/")
    assert "http://localhost:8000/static/site.css" in urls
    assert "http://localhost:8000/static/app.js" in urls
    assert "http://localhost:8000/static/logo.png" in urls
    assert "https://example.com/embed" in urls


def test_normalize_html_text():
    text = "Hello\n\n  world\t!"
    assert normalize_html_text(text) == "Hello world !"


def test_looks_like_html():
    assert looks_like_html("text/html", "<html><head></head></html>")
    assert looks_like_html(None, "<html><head></head>")
    assert not looks_like_html("application/json", "{\"ok\": true}")
