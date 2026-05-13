# Security Policy

Kai is a security research tool. Use it only on systems, repositories, and
deployments where you have explicit authorization to test.

## Supported Versions

The public repository is currently pre-1.0. Security fixes are applied to the
default branch unless a release branch policy is announced later.

## Reporting a Vulnerability

Please report vulnerabilities in Kai itself privately before opening a public
issue.

- Email: security@firstbatch.xyz
- Include: affected commit or version, reproduction steps, impact, and any
  relevant logs or proof-of-concept code.
- Do not include secrets, private target code, or third-party confidential data
  unless you have permission to share it.

We aim to acknowledge reports within 5 business days. If the address above is
not monitored for your organization, replace it before publishing this repo.

## Responsible Use

Do not use Kai to access, attack, degrade, or exploit systems without
permission. Reports and examples should avoid publishing working exploit
details for live third-party systems unless coordinated disclosure has already
completed.

## Sandbox Notice

The default local execution environment is intended for developer convenience,
not as a hard security boundary. Run untrusted target code in an isolated
environment such as a disposable container, VM, or CI worker.
