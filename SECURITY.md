# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | Yes |
| < 1.0 | No |

Security fixes are released for the latest 1.0.x version. Upgrade with `git pull` and `./start.sh` (Docker) or `sudo ./start.sh --service` (native).

## Reporting a vulnerability

Please report vulnerabilities in LazyEASM privately, not in a public issue:

- **GitHub private vulnerability reporting**: on the repository's **Security** tab, choose **Report a vulnerability**.
- **Email**: security@thelazies.net

Include the affected version or commit, how to reproduce the issue, and its impact. If you have a fix in mind, describe it in the report rather than opening a public pull request.

## What to expect

- An acknowledgement within **3 business days**.
- An initial assessment (confirmed or not, severity) within **10 business days**.
- A fix or mitigation as soon as possible, depending on severity; you will be kept informed of progress.
- Credit in the release notes and `CHANGELOG.md` if you wish, once a fix is released.

Please give us a reasonable time to release a fix before disclosing the issue publicly.

## Scope

In scope: the LazyEASM code in this repository (dashboard, API, worker, installers, Docker image).

Out of scope: vulnerabilities in the third-party targets LazyEASM finds (report those to their owners), and issues that require an attacker who already has the admin account or shell access to the server.

## Use LazyEASM responsibly

LazyEASM discovers and scans hosts on the internet. **Only scan what you are authorized to test.** Scanning systems without permission may be illegal where you or the target are located. A domain you submit is explored together with its subdomains, so submit only domains you own or have written permission to assess.
