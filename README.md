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
Start GPT4All
Ensure GPT4All is running with the Local API Server enabled (default: http://localhost:4891) or use a custom LLM API.

Run the App
Launch DNSGuardianAI by running:

```plaintext python3 server.py ```

This will start both:

- The DNS filtering service
- The Web Dashboard (available at http://localhost:5000)

Configuration
You can configure models, DNS ports, upstream DNS, and filtering behavior via:

- The config/config.json file, or

- The integrated Web UI

⚙️ Features
-LLM-based domain analysis with secondary checks:
  - WHOIS-based age registration
  - SSL certificate (SAN) validation
  - Broken link detection
- Web dashboard with:
  - Live statistics and log viewer
  - Editable configuration (models, ports, DNS settings, etc.)
