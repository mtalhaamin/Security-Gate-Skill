# Contributing

Thanks for helping. Bug reports, ideas and pull requests are all welcome.

## Report a problem or suggest something

- **Bug or wrong result:** open an [issue](../../issues/new/choose) using the *Bug report* form. Include the command you ran, the verdict, the tool versions from the report (`report.md` lists the Docker image digests) and your OS. Do **not** paste real secrets or a full report from a private project.
- **False alarm from a scanner:** that is usually the scanner, not this project. Open an issue only if the gate shows the wrong severity, location or status.
- **Security hole in this project itself:** please do not open a public issue; see [SECURITY.md](SECURITY.md).
- **New idea or tool:** open an issue with the *Feature request* form first, so we can agree on the approach.

## Change the code

You need Node 20+ (and Docker Desktop to run real scans). There are no npm packages to install.

```bash
git clone https://github.com/mtalhaamin/Security-Gate-Skill.git
cd Security-Gate-Skill
node security-gate/scripts/gate.selftest.mjs      # offline tests, no Docker needed
node security-gate/scripts/gate.mjs --preflight   # check Docker / .NET
```

Where things are:

| File | What it does |
|---|---|
| `security-gate/scripts/gate.mjs` | runs the scanners in Docker, parses their output, decides PASS / FAIL / INCOMPLETE |
| `security-gate/scripts/report-pdf.mjs` | builds the PDF from `report.json` |
| `security-gate/scripts/gate.selftest.mjs` | offline tests for the parsers, tool selection, DAST safety and verdict logic |
| `security-gate/SKILL.md` | instructions the AI coding tool follows |
| `install-skill.mjs` | copies the skill into Claude Code / Cursor / Codex / Antigravity folders |
| `docs/ADVANCED.md` | all options, troubleshooting, safety rules |

### Adding or changing a scanner

1. Add its Docker image to `IMAGES` in `gate.mjs` (pin a version) and a `run<Tool>` function.
2. Add a `parse<Tool>` function that returns findings (`tool`, `id`, `severity`, `package`, `location`, `title`). **Never copy secret values** into a finding.
3. Add the tool to `TOOLS`, `GROUPS` and `RUNNERS`, and a label in `report-pdf.mjs`.
4. Add a self-test with a small sample of the tool's real JSON output.
5. Run it for real on a small project and check the numbers against the tool's own output.
6. Update `docs/ADVANCED.md` and `security-gate/references/tools.md`.

## Rules for pull requests

- Keep it small and focused; one change per pull request.
- `node security-gate/scripts/gate.selftest.mjs` must pass. Say in the pull request how you tested a real scan.
- No new npm dependencies (the runner is dependency-free on purpose).
- A tool that cannot run must give `NOT-RUN` or `ERROR`, never a silent `PASS`.
- Never commit secrets, real scan reports (`.work/` is git-ignored) or private project data.
- Keep the README simple. Put detail in `docs/ADVANCED.md`.

By contributing you agree that your work is released under the [MIT License](LICENSE).
