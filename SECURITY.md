# Security policy

## Reporting a vulnerability in this project

If you find a security problem in Security Gate itself (for example a way to make it leak secret values, run commands outside its containers, scan a target it should refuse, or write outside the report folder), please report it **privately**:

1. Open the repository's **Security** tab.
2. Click **Report a vulnerability** (GitHub private vulnerability reporting).
3. Describe what you found, how to reproduce it and the impact.

Please do not open a public issue for security problems. This is a small project maintained in spare time, so replies are best effort, but reports are taken seriously and you will be credited if you wish.

## Supported versions

Only the latest release and the `main` branch receive fixes.

## What is not a vulnerability here

- A scanner (gitleaks, OSV-Scanner, Semgrep, Trivy, Grype, ZAP) reporting a false alarm on your project. Use a suppression with a reason (see `docs/ADVANCED.md`).
- A real vulnerability that a scanner finds in *your* project. That is what this tool is for; fix it in your project.
- Problems inside the scanners' own Docker images; report those to the scanner's project.

## Using Security Gate safely

- DAST (OWASP ZAP) sends attack-style traffic. Only point it at systems you own or are authorised to test; the gate refuses non-local targets unless you name the host and confirm.
- Scanners run in Docker with your project mounted read-only; only the report folder is writable.
- Local images are scanned through the Docker socket, which gives the scanner container control of your Docker engine. Avoid that on shared CI runners.
- Reports list internal file paths and package names. Treat them as confidential. Secret values are never written to a report.
