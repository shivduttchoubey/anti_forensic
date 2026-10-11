# Security Policy

This repository hosts the Universal Anti-Forensics Detection Engine, a tool designed to analyze static artifacts and monitor systems for suspicious behaviors. While the project is primarily a digital forensics and defensive tooling project, we take security and responsible disclosure seriously.

## Reporting a vulnerability

If you believe you have discovered a security issue in this project, please report it privately and responsibly.

Preferred methods:
- Use the GitHub Security Advisories feature for this repository, if enabled.
- If Security Advisories are not available, contact the maintainer through the GitHub profile associated with this repository and provide a private report.
- Do not open a public GitHub issue for a suspected vulnerability.

Please include:
- A clear description of the issue and affected component.
- Steps to reproduce the problem.
- Impact assessment and any proof-of-concept (POC) material, if safe and relevant.
- Your contact details so we can follow up.

## Scope

This policy applies to vulnerabilities in the repository code, including:
- Command-line parsing flaws and unsafe argument handling.
- Unsafe file processing or path traversal issues.
- Execution or command injection issues.
- Insecure deserialization or unsafe subprocess usage.
- Information disclosure or improper handling of analyzed artifacts.
- Abuse of live monitoring features that could affect host security.

The following are generally out of scope unless they result in a direct security impact in the project itself:
- General abuse of the underlying operating system or third-party tools.
- Issues in third-party dependencies that are not directly exploitable through this repository.
- Social engineering or phishing against maintainers.
- Automated scanning results without a demonstrated vulnerability.

## Responsible disclosure expectations

We ask researchers and users to:
- Refrain from public disclosure until the issue has been addressed or a reasonable remediation plan is in place.
- Avoid destructive testing, data loss, or access to unrelated systems.
- Do not exfiltrate sensitive data from the environment being analyzed.
- Limit testing to local or controlled environments.

## Safety and usage guidance

This project can analyze forensic artifacts and monitor live system activity. It should only be used in controlled, authorized environments.

Recommended practices:
- Run the tool only on systems you own, administer, or are explicitly authorized to test.
- Do not use the live monitoring features against production systems without approval.
- Treat the output of the tool as security-sensitive evidence and handle it appropriately.
- Review any configuration files, generated JSON reports, and execution logs before sharing them publicly.

## Supported versions

The project is under active development. The latest code on the default branch is the primary target for security fixes. If a release process is introduced later, version-specific support guidance may be added here.

## Review and remediation

We aim to acknowledge valid reports promptly and work toward a reasonable fix timeline. The exact turnaround time may vary based on complexity, impact, and availability of the maintainers.

Thank you for helping keep this project and its users safe.
