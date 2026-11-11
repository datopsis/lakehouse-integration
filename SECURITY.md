# Security boundary

This is a private integration fixture, not a production deployment or security
certification. The Trino draft PR pin is a deliberate pre-release exception for
testing only. Its vulnerability gate remains blocked by unfixed-upstream jars.
This test makes no security claim about Trino and never bypasses that release gate.
Strict provenance is independently mandatory and is not vulnerability scanning.

Lakekeeper login is disabled: anyone reaching its REST/management listener can
act on the catalog. This known gap is acceptable only on the internal private
test network. Trino explicitly opts into its documented insecure test mode.
Sail also explicitly opts into unauthenticated Spark Connect on the private
network. No service publishes a port. HTTP and PostgreSQL traffic are not encrypted.
The runner/host and all containers on that network are trusted; an internal
network does not protect against its host or another admitted member.

S3 uses per-run static credentials with only Read/Write/List on warehouse. The
master/filer/volume APIs bypass S3 authorization and must stay private. Bucket
provisioning uses a trusted administrative weed shell, not an admin S3 identity.
PostgreSQL has random admin and separate non-superuser Lakekeeper passwords;
local socket provisioning is trusted. Lakekeeper receives a fresh encryption key
retained across graceful recreation. No credentials are committed or GitHub
repository secrets required. Sail receives static AWS keys through its own `0600`
env file. Each container sees only its own secret mount or environment; S3 cannot
read PostgreSQL secrets. Runtime root filesystems are
read-only, all services are non-root, capabilities are dropped, and privilege
escalation is disabled. Writable volumes/tmpfs are documented in ARCHITECTURE.md.

Only sanitized logs are uploaded, for 14 days, after successful redaction. Raw
reports, credential inventories, and generated env files are ignored and remain
local. Never upload .runtime, .sources, full inspect output, Compose configuration,
or raw reports. Failed redaction prevents upload. The automatic issue job checks
out no code, reads no artifacts, and receives issue write access only after a
scheduled failure. Pull requests get a read-only token and no repository secrets.

Report a suspected vulnerability privately through the owning repository's
security reporting channel when available; do not put credentials or exploit
material in the weekly public failure issue. This repo does not grant permission
to change another repository's security policy or suppress its findings.

T10 passively captures only the Sail container's REST/S3 traffic to identify its
credential path. Raw HTTP evidence contains fixture credentials and remains
local until the same fail-closed inventory redaction as all other reports. No
packet files or source/environment directories are uploaded.
