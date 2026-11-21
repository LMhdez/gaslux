#!/usr/bin/env python3
"""Offline, fail-closed replay of the six *original* signed-ISO45 boot screenshots.

The SHA-pinned GitHub Actions ZIP binds screenshots, OCR, serial, preflight,
provenance and synthetic-disk audit. This module never operates QEMU or disks.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import zipfile
from pathlib import Path

from bazzite_iso45_passive_gate import Refusal, classify, validate_record
from bazzite_iso_public_readback import CONFIG_DIGEST, ISO_SHA256, PAYLOAD_DIGEST
from PIL import Image, UnidentifiedImageError

RUN_ID = 44822100590
ARTIFACT_ID = 14672623998
ARCHIVE_SHA256 = "ba434ddf46e892c80325608b87cf6933da88bda716e144cfd63df0a49904a00c"
FRAME_SHA256 = (
    "5ae8e1867d12d4c41001a745145d2c8fdca0b48bc3bb23325a4b69cb930cdca9",
    "f6b902eeacfa61214d8ba00be48713059dab8e8ed89a51c59ee3cbc23b9bfe61",
    "7448514e8fc4f8a857020867a900b410093c6afd3a097a8d51dcca0dfc713201",
    "c236fa939c5b085dfea58400514524da23665a0deb521f87cc51a9286302c386",
    "49d9e011fc6d30b61694ab451ebfd81bdd4ad545d5ef10edf1edf71ed8914d9a",
    "49d9e011fc6d30b61694ab451ebfd81bdd4ad545d5ef10edf1edf71ed8914d9a",
)
OCR_SHA256 = (
    "932394b245bab889daf8ee71df847a338c040b5bbd0c93c2a2d3102272ef885b",
    "6fe511516e239c352d3333dc797073cfec07e0b4ca4d5fd60d9eb6ecafb0757f",
    "3d13c07a0abb332c840a754cd1f596fa7695430fdf006e0948d3f11d42b67a2a",
    "afa670bbf4f742b6cc51de3044074bc2de167f9a7cd411775259359cb900ee79",
    "bc48aa8cb3b709480daeef1c627c410195fc37526b51f1765821ca46c68ab61f",
    "bc48aa8cb3b709480daeef1c627c410195fc37526b51f1765821ca46c68ab61f",
)
FRAME_SIZE = (1280, 800)
FRAME_COUNT = 6
REQUIRED = frozenset(
    {
        "bazzite-iso-public-readback.json",
        "readback-facts.json",
        "iso45-boot-preflight.json",
        "iso45-passive-boot-result.json",
        "iso45-boot-step-exit.txt",
        "iso45-serial.txt",
        "iso45-preboot-topology.txt",
        "iso45-screen-sha256.txt",
        "iso45-synthetic-before.json",
        "iso45-synthetic-verified.json",
        "iso45-synthetic-after.json",
        "iso45-synthetic-discard.json",
    }
    | {f"iso45-screen-{i}.png" for i in range(FRAME_COUNT)}
    | {f"iso45-ocr-{i}.txt" for i in range(FRAME_COUNT)}
    | {f"iso45-monitor-{i}.txt" for i in range(FRAME_COUNT)}
)


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise Refusal(reason)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def obj(files: dict[str, bytes], name: str) -> dict:
    try:
        value = json.loads(files[name].decode("utf-8"))
    except (KeyError, ValueError, UnicodeError) as exc:
        raise Refusal(f"Missing or invalid {name}") from exc
    require(isinstance(value, dict), f"Invalid object {name}")
    return value


def inspect_evidence(files: dict[str, bytes], candidate: dict) -> dict:
    """Inspect already SHA-verified archive members; never use OCR as a trust anchor."""
    require(REQUIRED.issubset(files), "Missing original boot evidence")
    report = obj(files, "bazzite-iso-public-readback.json")
    facts = obj(files, "readback-facts.json")
    validate_record(candidate, report, facts)
    preflight = obj(files, "iso45-boot-preflight.json")
    require(
        preflight.get("readbackResult") == "A"
        and preflight.get("isoSha256") == ISO_SHA256
        and preflight.get("ociManifestDigest") == PAYLOAD_DIGEST
        and preflight.get("configDigest") == CONFIG_DIGEST
        and preflight.get("measured", {}).get("sha256") == ISO_SHA256
        and preflight.get("measured", {}).get("sizeBytes") == 8377878528
        and preflight.get("measured", {}).get("isoReadOnly") is True
        and preflight.get("installationAuthorized") is False
        and preflight.get("guestCommandChannelAuthorized") is False,
        "ISO45 preflight mismatch",
    )
    old = obj(files, "iso45-passive-boot-result.json")
    require(
        old.get("result") == "C"
        and old.get("provenanceResult") == "A"
        and old.get("qemuBootStepExitCode") == "0"
        and old.get("screenshotCount") == FRAME_COUNT
        and old.get("cpuResumeRequested") is True
        and old.get("noWindowsDiskAttached") is True
        and old.get("guestDiskConfiguredReadOnly") is True
        and files["iso45-boot-step-exit.txt"].strip() == b"0",
        "Unrelated or unsuccessful original run",
    )
    prohibited = (
        "installationAuthorized",
        "partitionWriteAuthorized",
        "windowsEspWriteAuthorized",
        "nvramWriteAuthorized",
        "guestCommandChannelAuthorized",
        "getActionsObserved",
        "realGetActionsCaptured",
        "nativeInstallerWriteSetVerified",
        "runtimeAnacondaVersionProven",
        "runtimeBlivetVersionProven",
        "hostGuestIdentityAuthenticated",
        "rollbackVerified",
        "windowsBootVerified",
    )
    require(all(old.get(key) is False for key in prohibited), "Unexpected writer or runtime claim")
    require(
        old.get("anacondaDbusServiceObserved") is False
        and old.get("installerInterfaceIdentified") is False,
        "Unobserved installer asserted",
    )
    before = obj(files, "iso45-synthetic-before.json")
    require(
        before.get("firmware") == "uefi"
        and before.get("partitionTable") == "gpt"
        and before.get("fixtureOnly") is True
        and before.get("containsWindowsInstallation") is False
        and before.get("installationAuthorized") is False,
        "Unsafe or foreign synthetic disk",
    )
    for name, discarded in (
        ("iso45-synthetic-verified.json", False),
        ("iso45-synthetic-after.json", False),
        ("iso45-synthetic-discard.json", True),
    ):
        audit = obj(files, name)
        require(
            audit.get("gptVerified") is True
            and audit.get("baseUnchanged") is True
            and audit.get("labOnly") is True
            and audit.get("containsWindowsInstallation") is False
            and audit.get("installationAuthorized") is False
            and audit.get("overlayDiscarded") is discarded,
            f"Backing/overlay audit mismatch: {name}",
        )
    topology = files["iso45-preboot-topology.txt"].decode("utf-8", "replace")
    require(
        all(
            x in topology
            for x in (
                "GLXBAZRO001",
                "gpt-layout-scratch.qcow2",
                "bazzite-stable-live-amd64.iso",
            )
        ),
        "Unexpected virtual device topology",
    )
    serial = files["iso45-serial.txt"].decode("utf-8", "replace")
    require(
        "GRUB version 2.12" in serial and "Booting `Launch Bazzite Installer'" in serial,
        "Missing UEFI/GRUB optical boot markers",
    )
    declared = files["iso45-screen-sha256.txt"].decode("utf-8").splitlines()
    require(len(declared) == FRAME_COUNT, "Wrong number of SHA256 manifest lines")
    ocr_records = []
    for i, expected in enumerate(FRAME_SHA256):
        filename = f"iso45-screen-{i}.png"
        digest = sha(files[filename])
        require(digest == expected, f"Unapproved screenshot: frame {i}")
        match = re.fullmatch(r"([0-9a-f]{64})  (/.+/iso45-screen-\d+\.png)", declared[i])
        require(
            match is not None
            and match.group(1) == expected
            and match.group(2).rsplit("/", 1)[-1] == filename,
            f"Screenshot identity/order mismatch: {i}",
        )
        require(len(files[filename]) < 2_000_000, "Oversized screenshot")
        try:
            with Image.open(io.BytesIO(files[filename])) as img:
                img.verify()
            with Image.open(io.BytesIO(files[filename])) as img:
                img.load()
                require(
                    img.format == "PNG" and img.mode == "RGB" and img.size == FRAME_SIZE,
                    f"Unexpected PNG format or dimensions: frame {i}",
                )
        except (UnidentifiedImageError, OSError, ValueError) as exc:
            raise Refusal(f"Invalid screenshot: frame {i}") from exc
        require(sha(files[f"iso45-ocr-{i}.txt"]) == OCR_SHA256[i], "Unapproved OCR bytes")
        text = files[f"iso45-ocr-{i}.txt"].decode("utf-8", "replace")
        require(len(text) <= 8192, "Unbounded OCR text")
        monitor = files[f"iso45-monitor-{i}.txt"].decode("utf-8", "replace")
        require("VM status: running" in monitor, f"VM not running at frame {i}")
        ocr_records.append(text)

    # These PNG hashes identify the SIX frames examined directly by a reviewer.
    # OCR is a corroborating signal, not independent authenticity or a write grant.
    original = classify(ocr_records, guest_running=True, evidence_authenticated=True)
    require(
        original["result"] == "B"
        and original["liveEnvironmentRecognized"] is True
        and original["installerInterfaceIdentified"] is False,
        "Signed live desktop was not corroborated by multi-feature OCR",
    )
    return {
        "result": "B",
        "originalResult": "C",
        "reason": "Reviewed original Bazzite Portal desktop; OCR-only C was a false negative",
        "sourceWorkflowRunId": RUN_ID,
        "sourceArtifactId": ARTIFACT_ID,
        "sourceArchiveSha256": ARCHIVE_SHA256,
        "isoSha256": ISO_SHA256,
        "payloadDigest": PAYLOAD_DIGEST,
        "frameSha256": list(FRAME_SHA256),
        "frameCount": FRAME_COUNT,
        "frameDimensions": list(FRAME_SIZE),
        "visualLiveDesktopObserved": True,
        "installerDestinationObserved": False,
        "anacondaProcessVerified": False,
        "getActionsObserved": False,
        "writeSetVerified": False,
        "installationAuthorized": False,
        "partitionWriteAuthorized": False,
        "windowsEspWriteAuthorized": False,
        "nvramWriteAuthorized": False,
        "guestCommandChannelAuthorized": False,
        "rollbackVerified": False,
        "windowsBootVerified": False,
        "noWindowsDiskAttached": True,
        "syntheticBackingUnchanged": True,
        "syntheticOverlayDiscarded": True,
        "classificationScope": "Pinned, passively reviewed screenshot evidence only",
    }


def replay(path: Path, candidate: dict) -> dict:
    require(path.is_file() and not path.is_symlink(), "Missing or redirected archive")
    require(path.stat().st_size < 10_000_000, "Oversized replay archive")
    require(sha(path.read_bytes()) == ARCHIVE_SHA256, "Wrong original artifact ZIP SHA256")
    try:
        with zipfile.ZipFile(path) as z:
            members = z.infolist()
            names = [item.filename for item in members]
            require(len(names) == len(set(names)), "Duplicated ZIP member")
            require(all("/" not in x and "\\" not in x for x in names), "Nested ZIP member")
            require(
                all(item.file_size <= 2_000_000 and not item.is_dir() for item in members),
                "Unsafe ZIP entry",
            )
            files = {name: z.read(name) for name in REQUIRED}
    except (zipfile.BadZipFile, KeyError, OSError, RuntimeError) as exc:
        raise Refusal("Corrupt or incomplete source artifact") from exc
    return inspect_evidence(files, candidate)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        candidate = json.loads(args.candidate.read_text(encoding="utf-8"))
        result = replay(args.archive, candidate)
    except (Refusal, OSError, ValueError, UnicodeError, TypeError) as exc:
        parser.exit(2, f"REFUSED_REPLAY: {exc}\n")
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
