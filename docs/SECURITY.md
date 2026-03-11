# Security

This worker interacts with potentially hostile websites.

Security expectations:
- use non-browser HTTP requests only
- keep timeouts and response size caps in place
- do not execute site JavaScript
- do not store secrets in the repository
- keep raw large artifacts out of Convex
- treat redirects, TLS failures, and malformed responses as expected inputs

If a future change expands the attack surface, capture the new risk and mitigation in an ExecPlan before implementation.
