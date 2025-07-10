# DNSGuardianAI

```plaintext
██████╗ ███╗   ██╗███████╗   ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ██╗ █████╗ ███╗   ██╗   █████╗ ██╗
██╔══██╗████╗  ██║██╔════╝  ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗██║██╔══██╗████╗  ██║  ██╔══██╗██║
██║  ██║██╔██╗ ██║███████╗  ██║  ███╗██║   ██║███████║██████╔╝██║  ██║██║███████║██╔██╗ ██║  ███████║██║
██║  ██║██║╚██╗██║╚════██║  ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║██║██╔══██║██║╚██╗██║  ██╔══██║██║
██████╔╝██║ ╚████║███████║  ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝██║██║  ██║██║ ╚████║  ██║  ██║██║
```
DNSGuardianAI is an AI-powered tool designed to detect potentially harmful DNS queries.

🚀 How to Run

- Ensure GPT4All is running with the Local API Server enabled (default: http://localhost:4891) or use the URL of a custom LLM API.

- Launch DNSGuardianAI by running: ```python3 server.py ```

This will start both:

- The DNS filtering service
- The Web Dashboard (available at http://localhost:5000)

Configuration

You can configure models, DNS ports, upstream DNS, and filtering behavior via:

- The config/config.json file, or

- The integrated Web UI

⚙️ Features
- LLM-based domain analysis with secondary checks:
  - WHOIS-based domain age registration
  - SSL certificate (SAN) validation
  - Broken link detection
- Configurable Whitelists & Blacklists
  - Manually or automatically maintain lists for trusted and blocked domains to improve performance and skip redundant checks.
  - Use already available public blacklists by adding their URLs to maintain and update blocked domains automatically.
- Web dashboard with:
  - Live statistics and log viewer
  - Editable configuration (models, ports, DNS settings, etc.)
