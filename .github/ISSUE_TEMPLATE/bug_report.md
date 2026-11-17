---
name: Bug report
about: The gate gave a wrong result, crashed, or did not run
title: ''
labels: bug
assignees: ''
---

**What happened**
A short description of the problem.

**What you expected**

**Command you ran**
```bash
node security-gate/scripts/gate.mjs ...
```

**Result**
Verdict (PASS / FAIL / INCOMPLETE) and the lines of the summary that look wrong. Do not paste real secrets.

**Your setup**
- OS:
- Docker Desktop version:
- Node version (`node --version`):
- .NET SDK version (`dotnet --version`), if a .NET project:
- Image versions: copy the lines from `.work/security-gate/report.md` that start with `> <tool>:`

**Anything else**
Screenshots, or the output of `node security-gate/scripts/gate.mjs --preflight`.
