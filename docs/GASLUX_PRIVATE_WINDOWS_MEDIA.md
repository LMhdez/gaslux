# Private Windows media preflight

Existing Lifecycle daily schedule, no new scheduler. Opt-in only on trusted
main, never on pull_request, with a dedicated GitHub environment
gaslux-windows-media. Do not enable the repository variable
GASLUX_WINDOWS_MEDIA_ENABLED=true until the environment is created and
restricted to main and the custodian has approved its use.

The custodian must obtain legally authorized official Windows test media
(Windows 10/11 as required by the actual acceptance platform), verify its
provenance and license independently and put it in private HTTPS storage.
No public GitHub release, artifact, repository or Windows image cache.

Environment secrets:
- GASLUX_WINDOWS_MEDIA_URL: private HTTPS download URL, no redirect.
- GASLUX_WINDOWS_MEDIA_AUTHORIZATION_REF: private custodian license/provenance
  record reference (not the license itself).

Environment variables:
- GASLUX_WINDOWS_MEDIA_HOST: exact independently configured HTTPS host.
- GASLUX_WINDOWS_MEDIA_SHA256: independently obtained expected SHA256.
- GASLUX_WINDOWS_MEDIA_SIZE_BYTES: exact verified length in bytes.

The runner checks available space and streams into a private temporary
directory, with an exact byte cap, SHA256 and cleanup. The report never
contains the URL, authorization reference, image path or image. Download
is daily or explicit dispatch, not every 30 minutes. The URL must remain
valid for the scheduled run; credential rotation is a custodian concern.

This does not establish independent licensing authorization, bootability,
Windows installation, disk write ownership, quota, snapshots, dual boot,
recovery or release readiness. All such flags remain false. The actual
Windows media bytes plus the pinned 3,091,660,800-byte Mint media replace
the provisional 4-GiB allowance for the capacity report: 60 GiB disk,
8 GiB snapshot planning, 8 GiB reserve plus both ISOs. A total above 85 GiB
blocks the current compact design, requiring a reviewed revised budget.
A passing planning measurement is not a real write quota.
