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


## Reconciled Lifecycle composition (2026-11-24)

This composition preserves the reviewed heads of #416
(5cfb82657b7ea58fc8c750a2ae1474643426f30c) and #418
(07938cfeef55fc684bb85ddfd9a000a49c78160e), both based on
main d408ffa603272007d9cb0c2c896ed1789f775a80. It carries the
#418 files unchanged except the workflow and this documentation, and
adds the #416 readiness job with an explicit trusted-main ref guard.
The original PRs remain open until independently reviewed reconciliation.
Neither previous Safety verdict nor CI is transferred to the composition.

The readiness job is independent of the private-media job: it receives
no media credentials, may observe capacity and PR state, and never sets
media or writer authority. The private-media job requires the existing
daily cron or an explicit opt-in dispatch, repository enablement and
the protected environment; it never executes during pull_request CI.
Both use the existing scheduler and independent JSON artifacts. Contract
CI checks both job boundaries, while a successful PR check does not
demonstrate either job executing on main.

Activation order:
1. Independently review this exact composition and validate CI and main
   protection; integrate only within the existing applicable authority.
2. Configure gaslux-windows-media environment with main-only deployment
   rules and a custodian independent of implementation. Keep enablement off.
3. Privately provision authorized test media with independently verified
   source, SHA256, byte size and authorization reference, never via chat,
   public repository or public artifacts.
4. After independent approval, enable the private-media preflight and
   dispatch on main; record exact run, job, artifact and digest.
5. Observe readiness and media reports independently. Never combine
   capacity measurements from separate runners into a guest quota proof.
6. A separate approved disposable-VM producer must prove actual Windows
   identity, quota/restore and installation/dual-boot/recovery. Until then
   no VM writer, distro merge or release authority.

Historical #388 (run 45067845469) reported actual 60-GiB physical
reservation and synthetic overlay reset but BLOCKED_MEDIA, 2/11
checkpoints. The current runner and exact candidate require fresh evidence.
No live environment configuration or credentials are created by this PR.
