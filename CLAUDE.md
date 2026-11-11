# Repository guidance

Read and follow [AGENTS.md](AGENTS.md). Its owner decisions are binding for all agents.
Never weaken checks, skip the encoding canary, or accept provenance gaps. Pins are
reviewed one-line changes in images.lock.json. Read README.md, SECURITY.md, and the
architecture/roadmap documents before implementation. Report actual CI evidence and
anything not verified. Do not modify the retained spike/feasibility branch.

The owner superseded the amd64-only decision on 2026-11-11: build and run the
complete integration test natively on amd64 and arm64, from the same pinned
commits. Use each repository's architecture-specific or shared artifact lock.
No QEMU, emulation, architecture-specific test exemptions, or weakened gates.
The required check remains exactly `Integration`, aggregating both native jobs.
