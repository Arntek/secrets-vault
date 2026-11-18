# Security policy

secrets-vault holds credentials, so we take reports seriously and would rather hear about a possible problem early than late.

## Reporting a vulnerability

**Please do not open a public issue, pull request or discussion for a security problem.**

Report it privately through GitHub: go to this repository's **Security** tab and choose **Report a vulnerability** (GitHub private vulnerability reporting). Only the maintainers can see the report.

Please include:

- what you found and the impact you think it has,
- the version or commit, and your OS,
- steps to reproduce, or a proof of concept,
- whether you'd like to be credited, and how.

Never include real secrets in a report. Use made-up values.

## What to expect

- We aim to acknowledge a report within 3 working days and give a first assessment within 10.
- We'll keep you updated while we fix it, and agree a disclosure date with you. Our default is to publish an advisory once a fixed release is available, within 90 days of the report.
- We credit reporters in the advisory unless you ask us not to.

## Scope

In scope: this repository's code, release artifacts and install packages (Homebrew tap, npm package), and the vault file format.

Out of scope: attacks that need an already-compromised user account or root on the machine running vault (see [docs/threat-model.md](docs/threat-model.md) for what vault does and doesn't protect against), social engineering, and denial of service against GitHub.

## Supported versions

Until 1.0, only the latest release gets security fixes.
