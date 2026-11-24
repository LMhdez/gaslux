# Q4OS historical archive verifier — diagnostic only

The isolated offline verifier is `auto_tests/tools/verify_q4os_action_archives_offline.py`.
It derives from the historical source in [#270](https://github.com/LMhdez/gaslux/pull/270)
(blob `ac97df862378955fbbeabd8426d4a0fbd9753603`), but does **not** import
`installer_observer.q4os`, `replay`, `locators`, screenshot navigation, OCR,
QMP/RFB, or input and storage writers. Only `installer_observer.evidence` is reused.

The exact historical `q4os-manifest.json` is copied unchanged from Git blob
`16f38eb774c7149b0c73cc463e1af4e09073d5dc`.
Its pinned canonical SHA-256 is
`e28485fc2e2ce8536c5e8f4dab30c4f0b44de74a70dece9b4897155e43598956`.

## Offline usage

Supply four separate files named `<artifactId>.zip` in `--zip-dir`, and
four GitHub artifact-metadata JSON files named `<artifactId>.json` in
`--metadata-dir`. Use a checkout with the fixed manifest:

```sh
python -m auto_tests.tools.verify_q4os_action_archives_offline \
  --manifest docs/distro-backends/evidence/q4os-manifest.json \
  --zip-dir /path/to/local/zips \
  --metadata-dir /path/to/local/metadata
```

Artifact IDs, in order: `14587306682`, `14586773677`, `14590616864`,
`14589299655`. Pinned Actions run IDs: `44641233701`, `44648406729`.
No ZIPs, screenshots, user credentials or external metadata are shipped with the verifier.

Each ZIP is read from a bounded, identity-checked regular-file descriptor.
The in-memory bytes are hashed and then passed directly to
`zipfile.ZipFile(io.BytesIO(...))` without reopening the pathname.
No entries are extracted, executed or written to disk.

A success decision `HISTORICAL_ARTIFACT_MATCHED` means that **supplied bytes**
match the pinned manifest: four whole-ZIP digests, declared reports and PNG
digests, ZIP structure, workflow metadata fields, 40 screenshot entries and 36
historical transition records. Extra legacy entries under `calamares-inspect/` (including nested
`native-hooks/`) and non-PNG entries under `evidence/` are permitted only
with bounded canonical paths, regular-file ZIP types and mandatory whole-ZIP
SHA-256 identity. Optional entries are decompressed for CRC validation, but
their individual SHA-256 values are not separately pinned in the manifest.
A different ZIP, even with self-consistent supplied metadata, is refused
against the hardcoded historical archive SHA-256.

The supplied GitHub metadata can be forged. Even fully matching metadata
does **not** authenticate GitHub as the source: the report always contains
`EXTERNAL_PROVENANCE_UNPROVEN`. The verifier does not authenticate upstream
Q4OS ISO signatures, guest ownership, the accuracy of historical visual
assertions, the Windows environment, or an installer. The synthetic CI test
result is `SYNTHETIC_TEST_PASSED` only, never actual historical matching.

All execution authority flags remain false:
`inputAuthorized`, `diskWritesAuthorized`, `trustBoundaryIndependent`,
`productionInstallationAuthorized`, and `releaseEligible`.

## Deliberately excluded from #270

Historic screenshots, visual gates, locator/OCR selectors, replay engine,
controller lease and QMP/RFB navigation remain solely in experimental branches.
No QEMU, guest input, Calamares, Windows Setup, bootloader, ESP/BCD/WinRE/NVRAM
operation or recovery proof is introduced here. No merge is authorized without
review of the exact head and green CI.
