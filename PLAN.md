Prioritized Fingerprinting Roadmap for Scam Website Crawler

This plan contains multiple fingerprinting steps. 
Design your pipeline so each step writes its own output under the same scan_id.
For example:
scan_metadata[scan_id]: URL, start time, status
fingerprint_html[scan_id]: hashes, raw html, fuzzy hash
fingerprint_favicon[scan_id]: raw, mmh3 hash
fingerprint_tls[scan_id]: cert info, fingerprint
fingerprint_assets[scan_id]: JS/CSS hashes, external domains
fingerprint_analytics[scan_id]: GA/FB pixel IDs, etc.
fingerprint_network[scan_id]: IP, ASN, JARM
Then you create the final profile:
site_profile = {
  "site_id": "scamdomain.xyz",
  "latest_scan_id": "...",
  "cluster_id": "...",
  "last_seen": "...",
  "fingerprint": {merged data}
}
(Though you can chose the best data model as you are closest to the task)

That way:
You can rerun just one failed fingerprint step (e.g. JARM timed out)
You can compare multiple scans over time for diffs
You don’t lose work if a scan dies halfway


do not store HTML or other large artifacts directly in Convex. Convex is great for structured data, but:
Instead:
Use object storage for:
Raw HTML
Favicons
JS/CSS/image assets (if you keep them)

Screenshots or archives in future
Then in Convex, just store:
A filename or object key (e.g. "html_key": "scans/2026-01-23/scamdomain.xyz/index.html")
A content hash for verification (e.g. "html_sha256": "...")
Any metadata needed (e.g. content length, mime type)

For now we will have not setup an object storage. So just implement TODOs at points that require object storage. We can fill them in later.

1. HTTP Response Collection
Fetch Homepage: Use Python’s requests (or similar HTTP library) to perform a raw GET request to the scam website’s homepage (no headless browser, no authentication).
Status & Headers: Record the HTTP status code (and any redirect information) and capture all response headers. Pay special attention to headers like Server, X-Powered-By, Set-Cookie, and Content-Type. These can reveal the server software or frameworks in use.
Basic Metadata: Note the response’s content length and retrieval timestamp. These basic attributes, while not unique, provide context and could coincide for identical deployments (e.g., same kit version yielding the same byte size).
2. HTML Content Hashing (Exact)
Store Raw HTML: Save the exact HTML source of the homepage after the HTTP response is received.
Compute Hash: Generate a cryptographic hash of the HTML (e.g., SHA-256 using Python’s hashlib). This yields a content fingerprint for exact comparison.
Compare for Duplicates: Use the hash to quickly identify duplicate pages. If two pages produce the same SHA-256 hash, they are byte-for-byte identical – a strong sign of a copy or kit reuse.
Normalization (Optional): If trivial dynamic differences are present (timestamps, random IDs), implement a simple normalization (remove or replace those before hashing) to avoid false mismatches.
3. HTML Content Fuzzy Hashing (Similarity)
Generate Fuzzy Hash: Utilize a fuzzy hashing algorithm like ssdeep (open-source library pydeep for Python) to produce a similarity digest of the HTML content[2]. This algorithm computes a context-triggered piecewise hash that tolerates small differences in input.
Cluster by Similarity: Compare the ssdeep output of the new page against a repository of existing fuzzy hashes. If the similarity score exceeds a threshold (e.g., >80%), group those pages together. High similarity implies the underlying HTML structure is largely the same.
Database of Hashes: Maintain an indexed database of ssdeep hashes for all scraped homepages. Upon each new crawl, automatically calculate its fuzzy hash and retrieve any existing pages with non-zero matches, recording the scores.
Iterate and Refine: Continuously refine clustering by adjusting similarity thresholds and possibly using additional fuzzy hashing algorithms (such as TLSH) as needed – but start with ssdeep as it’s widely used and supported.
4. Favicon Extraction and Hashing
Retrieve Favicon: Attempt to download the site’s favicon by requesting /favicon.ico via HTTP. Many scam sites use a favicon (often the logo of the brand they’re spoofing or a generic icon).
Compute Favicon Hash: Calculate a hash of the favicon file bytes using MurmurHash3 – the same method used by Shodan[4]. In Python, the mmh3 library can produce this hash (by hashing the favicon bytes, often after base64-encoding them as Shodan does)[5].
Record and Compare: Store the favicon hash and compare it across sites. If multiple sites share the same hash, they are very likely using the same icon file (and thus possibly the same kit or brand decoy).
5. Linked Asset and Resource Fingerprinting
Parse HTML for Assets: Use an HTML parser (e.g., BeautifulSoup) to extract references to linked resources in the homepage HTML:
Local Assets (CSS, JS, Images): For each <script src="">, <link href="">, or <img src=""> that points to the same domain (or a relative path), fetch that resource via HTTP. Compute a SHA-256 (or MD5) hash of the content. This yields fingerprints for the kit’s static files (stylesheets, JavaScript, images).
Compare Asset Hashes: Compare these asset hashes across the dataset. If two different sites have an identical image or script hash (for example, the same logo.png file content or an identical form.js script), it’s a strong indicator they originate from the same kit or have a common developer. Even if the HTML is tweaked, shared static resources are telling. Record the file names and hashes for clustering.
Extract External References: Identify any external domains in the HTML (e.g., scripts from CDN or iframes to other domains):
Legitimate vs. Suspicious: Filter out known legitimate domains (e.g., Google APIs, Cloudflare, CDNs for libraries) to focus on unknown or suspect ones.
Reused Domains: Flag any external domain that appears across multiple scam sites. For instance, if several pages include <script src="http://badcdn.example.com/kit.js">, that domain likely belongs to the scam operator’s infrastructure, linking those sites together.
Identify Tracking Codes: Search the HTML for analytics or tracking IDs that might indicate a common owner:
Use regex to find Google Analytics identifiers (Universal Analytics UA-########-# and Google Analytics 4 G-######## codes)[8], as well as other trackers (e.g., Google Tag Manager IDs, Facebook Pixel IDs).
If multiple sites share the same tracker ID, it’s a nearly certain link – the scammer reused their analytics code across sites. List any found IDs in the site’s fingerprint profile.
6. TLS Certificate and Network Fingerprinting
SSL Certificate Collection: For HTTPS sites, capture the X.509 certificate from the TLS handshake. This can be done in Python by inspecting the requests response (response.raw._connection in urllib3) or using ssl/socket directly. Extract certificate details:
The SHA-1/SHA-256 fingerprint of the certificate (hash of the DER encoded cert).
The subject and issuer names, and validity period.
Certificate Reuse Analysis: Compare the certificate fingerprints among crawled sites. If two different domains present the exact same certificate (e.g., a certificate valid for multiple names, or a reused self-signed cert), that is an immediate link. Even certificates from the same issuer with identical subject fields could indicate the same entity obtained them in bulk. A single certificate’s fingerprint can be used as a pivot to find all domains that certificate secures[10].
Hosting IP and ASN: Record the resolved IP address of the homepage request. Optionally, map this IP to an Autonomous System Number (ASN) or hosting provider using an IP-to-ASN database (open-source data like MaxMind ASN). Track which sites share the same IP or ASN.
JARM Fingerprinting (Advanced): Implement active TLS fingerprinting using JARM (open-source on GitHub by Salesforce). JARM sends a series of crafted TLS Client Hello packets and generates a 62-character fingerprint of the server’s TLS configuration[11][12]. Use a Python JARM library to get this fingerprint for each site.
Compare Network Fingerprints: Use the collected network identifiers (IP, ASN, cert fingerprint, JARM hash) to link sites. For example:
Sites on the same IP address or same small ASN range could be operated by the same group (or bulletproof hosting provider). Threat infrastructure is often reused; one IP might host multiple scam domains[13].
Sites sharing a certificate fingerprint are definitely related (e.g., a wildcard cert or reused certificate for multiple scams) – a single cert hash might tie together many phishing sites[10].
Sites with identical JARM fingerprints suggest an identical server software stack. This can cluster servers that are configured the same way, potentially pointing to the same operator’s environment or appliance across different IPs. JARM has been shown to group malicious servers by their TLS config even if hostnames differ[11].
7. Clustering and Cross-Referencing
Profile Aggregation: For each crawled site, consolidate all the collected fingerprint data into a profile (content hashes, favicon hash, asset hashes, headers, trackers, cert, IP, etc.). This comprehensive fingerprint can be stored in a database or JSON for analysis.
Intra-Set Clustering: Implement logic to automatically cluster these profiles based on shared or similar features:
Hard links: Directly group sites that share an exact fingerprint (e.g., same HTML hash, same favicon hash, same GA ID, same cert or IP). These indicate the same kit or infrastructure with high confidence.
Soft links: For similarity measures (fuzzy hash scores, JARM, similar server headers), define thresholds or scoring systems to suggest a link. For example, ssdeep similarity >90% or JARM match could add to a cumulative “similarity score” between two site profiles. Use an unsupervised clustering algorithm (like DBSCAN or hierarchical clustering) on these feature vectors to automatically form clusters of related sites.
Cross-Cluster Pivoting: Take distinctive fingerprints from one cluster and search externally for new sites:
Query Shodan by favicon hash to find additional IPs using that icon (this can reveal scam sites we haven’t crawled yet that use the same kit’s favicon)[6].
Search certificate transparency logs or services by the certificate fingerprint to discover other domains that were issued the same cert (often available via CT search APIs).
Use search engines or specialized tools (e.g., PublicWWW or Google dorks) to look for unique strings or codes from the kit (such as a specific phrase in the HTML or the Google Analytics ID) on other sites. For instance, a reverse Google Analytics lookup can list all domains using a given UA code[14].
Iterate Expansion: Feed any newly found domains back into the crawler to fingerprint them, and see if they join an existing cluster or form a new one. Over time, this builds a map of scam website networks operated by the same actors.

[1] [2] [3]  Fuzzy Hashing: A New Weapon in the Fight Against Phishing
https://www.dqindia.com/business-solutions/fuzzy-hashing-a-new-weapon-in-the-fight-against-phishing-6918845
[4] [5] [6] [7] Hunting phishing websites with favicon hashes - SANS ISC
https://isc.sans.edu/diary/27326
[8] [9] [14] Tracking the Tracker: OSINT with Google Analytics IDs | by Coolman | Medium
https://medium.com/@tracker221B/tracking-the-tracker-osint-with-google-analytics-ids-20f7eccc058b
[10] [13] Practical AWS Threat Hunting: Exposing C2s, Phishing Kits, and Open Directories with Hunt.io
https://hunt.io/glossary/aws-threat-hunting
[11] [12] Easily Identify Malicious Servers on the Internet with JARM - Salesforce Engineering Blog
https://engineering.salesforce.com/easily-identify-malicious-servers-on-the-internet-with-jarm-e095edac525a/
