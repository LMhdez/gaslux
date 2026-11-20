"""Reviewed Q4OS lab profile. All paths and executable validators originate in code."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import asdict
from pathlib import Path

from auto_tests.tools import gaslux_q4os_summary_visual_gate as summary

from . import _q4os_pixels as pixels
from .evidence import Refusal, basename, canonical, digest, parse, read, sealed
from .locators import Method, Surface
from .models import Action, DistributionIdentity, InstallerIdentity, InterfaceMap, Transition
from .replay import RecordedState, Recording, replay
from .schema import Profile, load_map, validate
from .screenshot import Screenshot

ROOT = Path(__file__).resolve().parents[2]
MAP = ROOT / "docs/distro-backends/ui-maps/q4os.json"
MANIFEST = ROOT / "docs/distro-backends/evidence/q4os-manifest.json"
ORIGINALS = ROOT / "auto_tests/fixtures/installer_observer"
PROFILE = Profile(
    DistributionIdentity(
        "q4os",
        "6.10 r2",
        "1df141eaa342bbfd0092791a60f1ae9cf5230e8ebb472f87fcb463203e3eb95d",
        1851392000,
    ),
    InstallerIdentity("Calamares", "1:3.3.14-deb13.1.3"),
    ROOT / "schemas/distro-ui-map.schema.json",
    "37865526a62d432ebf34e4003d96998297e16ca373d10729fe6f751b15a802e1",
    {
        "double-click installer icon": Action.OPEN_WIZARD,
        "advance to Location": Action.NEXT,
        "advance to Keyboard": Action.NEXT,
        "advance to Software": Action.NEXT,
        "select native desktop profile": Action.SELECT_PROFILE,
        "advance to Partitions": Action.NEXT,
        "select proposal only, never execute installer": Action.PREVIEW,
        "advance to Users without installation": Action.NEXT,
        "populate synthetic guest fields": Action.FILL_FIXTURE,
        "advance to Summary": Action.NEXT,
    },
)
MANIFEST_SHA = "e28485fc2e2ce8536c5e8f4dab30c4f0b44de74a70dece9b4897155e43598956"
REGION = (300, 70, 975, 600)
# ROI shared by all four original desktop frames. A still-visible desktop icon
# behind an open wizard also passes the old after_close predicate.
DESKTOP = "b0316bba84a65e0d6a80c3d9f1077b87c874a91fddd0d0f067673c1ce05f9ea1"
FILLED_FIELDS = (
    (324, 182, 730, 418),
    "c892ac4dd9b13c8396c89cbb10482edc3dc97c27c1796c9f83f417a8bc8879ee",
)
GATES = {
    "calamares-welcome": pixels.verified_native_calamares_welcome,
    "calamares-location": pixels.verified_native_calamares_location,
    "calamares-keyboard": pixels.verified_native_calamares_keyboard,
    "calamares-software-unselected": pixels.verified_native_calamares_software_unselected,
    "calamares-software-desktop-selected": pixels.verified_native_calamares_desktop_selected,
    "calamares-partitions": pixels.verified_synthetic_calamares_partitions_view,
    "calamares-partitions-proposal-only": pixels.verified_synthetic_calamares_partitions_selected,
    "calamares-users-unfilled": pixels.verified_native_calamares_users,
}
# No accessibility or widget tree was captured through VNC. Scaling was unmeasured.
SURFACE = Surface(unproven=frozenset({Method.POINT, Method.BOX}))


def recognize(frame: Screenshot) -> Iterator[str]:
    for state, gate in GATES.items():
        if gate(frame.image):
            yield state
    if frame.roi(REGION) == DESKTOP and pixels.verified_after_close(frame.image):
        yield "desktop-before-launch"
    if all(
        frame.roi(box) == sha for box, sha in (summary.TITLE, summary.USERS_SIDEBAR, FILLED_FIELDS)
    ):
        yield "calamares-users-filled"
    if all(
        frame.roi(box) == sha
        for box, sha in (
            summary.SUMMARY_TOP_BAR,
            summary.SUMMARY_SELECTED_SIDEBAR,
            summary.SUMMARY_PARTITION_PLAN_HEADER,
        )
    ):
        yield "calamares-summary"


def validate_edge(edge: Transition, before: Screenshot, after: Screenshot) -> None:
    if edge.action is Action.FILL_FIXTURE:
        summary.users_with_dummy_data(before.png, after.png)
    elif edge.target == "calamares-summary":
        summary.summary_only(before.png, after.png)


def _report(directory: Path, archive: dict, name: str) -> dict:
    raw = read(directory / basename(name))
    if digest(raw) != archive["reports"].get(name):
        raise Refusal(f"Original report SHA-256 mismatch: {name}")
    return parse(raw)


def recordings(mapping: InterfaceMap, manifest_path: Path, root: Path) -> Iterator[Recording]:
    manifest = parse(read(manifest_path))
    validate(manifest, ROOT / "schemas/distro-ui-evidence.schema.json")
    if digest(canonical(manifest)) != MANIFEST_SHA:
        raise Refusal("Manifest differs from reviewed four-artifact index")
    archives = {a["artifactId"]: a for a in manifest["archives"]}
    for run in manifest["runs"] + manifest["summaryRuns"]:
        aid = run["artifactId"]
        archive = archives[aid]
        directory = root / str(aid)
        doc = _report(directory, archive, "ui-screenshots-report.json")
        rows = tuple(RecordedState(r["state"], r["path"], r["sha256"]) for r in run["screenshots"])
        edges = tuple((e["from"], e["to"]) for e in run["transitions"])
        extended = "summary-experiment.json" in archive["reports"]
        expected = {
            "kind": "q4os-genuine-visual-experiment",
            "runId": run["runId"],
            "replica": run["replica"],
            "attempt": run["attempt"],
            "isoSha256": mapping.identity.sha256,
            "isoSizeBytes": mapping.identity.size_bytes,
            "labSourceCommit": manifest["labSourceCommit"],
            "summaryVisited": extended,
            "windowsDiskAttached": False,
            "installationAuthorized": False,
            "nativeCalamaresInstallExecuted": False,
        }
        if any(doc.get(k) != v for k, v in expected.items()):
            raise Refusal("Original lab identity or safety report mismatch")
        for state, recorded, original in zip(
            mapping.states[:9], rows[:9], doc["states"], strict=True
        ):
            if (
                (state.id, state.screenshot, state.gate, recorded.sha256)
                != (original["state"], original["png"], original["visualGate"], original["sha256"])
                or recorded.id != state.id
                or original["visualGateVerified"] is not True
                or tuple(original["resolution"]) != mapping.resolution
            ):
                raise Refusal("State evidence mismatch")
        for i, (edge, original) in enumerate(zip(edges[:8], doc["transitions"], strict=True)):
            if (
                edge != (original["from"], original["to"])
                or original["centralPixelTransition"] is not True
                or (rows[i].sha256, rows[i + 1].sha256)
                != (original["beforeSha256"], original["afterSha256"])
            ):
                raise Refusal("Transition evidence mismatch")
        durations = [None] * len(edges)
        if extended:
            proof = _report(directory, archive, "summary-experiment.json")
            expected = {
                "replica": run["replica"],
                "runId": run["runId"],
                "phase": "summary-observed",
                "sourceCodeCommit": manifest["labSourceCommit"],
                "partitionWriterAuthorized": False,
                "syntheticCredentialsOnly": True,
                "summaryVisualGatePassed": True,
                "calamaresInstallClicked": False,
                "windowsDiskAttached": False,
                "beforeScreenshot": rows[-2].filename,
                "beforeSha256": rows[-2].sha256,
                "afterScreenshot": rows[-1].filename,
                "afterSha256": rows[-1].sha256,
            }
            if any(proof.get(k) != v for k, v in expected.items()) or proof["elapsedMs"] <= 0:
                raise Refusal("Summary proof mismatch")
            durations[-1] = proof["elapsedMs"]
        yield Recording(
            run["runId"],
            run["replica"],
            aid,
            directory,
            rows,
            edges,
            tuple(durations),
            archive["workflowCommit"],
        )


def replay_q4os(
    map_path: Path = MAP, manifest_path: Path = MANIFEST, root: Path = ORIGINALS
) -> dict:
    mapping = load_map(map_path, PROFILE)
    sessions = []
    for recording in recordings(mapping, manifest_path, root):
        try:
            sessions.append(replay(mapping, recording, recognize, validate_edge, REGION))
        except (ValueError, OSError) as exc:
            raise Refusal(f"Artifact {recording.artifact_id}: {exc}") from exc
    return sealed(
        {
            "version": 1,
            "mode": "historical-replay",
            "distribution": asdict(mapping.identity),
            "installer": asdict(mapping.installer),
            "map_sha256": PROFILE.map_digest,
            "evidence_index_sha256": MANIFEST_SHA,
            "live_input_count": 0,
            "sessions": sessions,
        }
    )
