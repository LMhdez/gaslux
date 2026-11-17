"""Fail-closed post-install GPT and installed first-boot identity binding."""

import copy
import struct
import sys
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "auto_tests/tools"))
from gaslux_popos_native_gpt_reconcile import (  # noqa: E402
    ROOT_FIRST,
    ROOT_LAST,
    GptRefusal,
    reconcile_linux_only,
)

ESP = uuid.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b")
LINUX = uuid.UUID("0fc63daf-8483-4772-8e79-3d69d8477de4")


def entry(kind, guid, first, last, name="", attrs=0):
    payload = name.encode("utf-16-le")
    return (
        kind.bytes_le
        + guid.bytes_le
        + struct.pack("<QQQ", first, last, attrs)
        + payload.ljust(72, b"\x00")
    ).hex()


def evidence():
    entries = ["00" * 128 for _ in range(128)]
    entries[0] = entry(ESP, uuid.UUID(int=1), 2048, ROOT_FIRST - 1, "GASLUX-OWNED-ESP")
    entries[1] = entry(LINUX, uuid.UUID(int=2), ROOT_FIRST, ROOT_LAST, "GASLUX-OWNED-ROOT")
    before = {
        "mbrSha256": "a" * 64,
        "primary": {"diskGuid": "ab" * 16, "current": 1},
        "backup": {"diskGuid": "ab" * 16, "current": 67108863},
        "entries": entries,
    }
    after = copy.deepcopy(before)
    after["entries"][1] = entry(LINUX, uuid.UUID(int=3), ROOT_FIRST, ROOT_LAST - 1)
    return before, after


def test_native_root_reconciles_and_never_authorizes_production():
    before, after = evidence()
    proof = reconcile_linux_only(before, after)
    assert proof["rootPartuuidAfter"] == str(uuid.UUID(int=3))
    assert proof["rootLastLbaAfter"] == ROOT_LAST - 1
    assert proof["rootPartuuidBefore"] != proof["rootPartuuidAfter"]
    assert proof["requiresPostInstallPlanReconciliation"] is True
    assert proof["ownedEspGptEntryIdentical"] is True
    assert proof["productionInstallationAuthorized"] is False
    assert proof["windowsDualBootProven"] is False


def test_unchanged_partition_table_is_allowed():
    before, _ = evidence()
    proof = reconcile_linux_only(before, before)
    assert proof["requiresPostInstallPlanReconciliation"] is False


@pytest.mark.parametrize(
    "tamper",
    [
        "esp",
        "third_partition",
        "mbr",
        "disk_guid",
        "root_start",
        "root_end",
        "root_kind",
        "root_attrs",
        "root_name",
        "zero_root_guid",
        "unknown_field",
    ],
)
def test_unauthorized_gpt_mutations_refused(tamper):
    before, after = evidence()
    if tamper == "esp":
        after["entries"][0] = entry(ESP, uuid.UUID(int=44), 2048, ROOT_FIRST - 1)
    elif tamper == "third_partition":
        after["entries"][2] = entry(LINUX, uuid.UUID(int=40), ROOT_LAST + 1, ROOT_LAST + 10)
    elif tamper == "mbr":
        after["mbrSha256"] = "c" * 64
    elif tamper == "disk_guid":
        after["primary"]["diskGuid"] = "cd" * 16
    elif tamper == "root_start":
        after["entries"][1] = entry(LINUX, uuid.UUID(int=3), ROOT_FIRST + 1, ROOT_LAST - 1)
    elif tamper == "root_end":
        after["entries"][1] = entry(LINUX, uuid.UUID(int=3), ROOT_FIRST, ROOT_LAST - 2)
    elif tamper == "root_kind":
        after["entries"][1] = entry(ESP, uuid.UUID(int=3), ROOT_FIRST, ROOT_LAST - 1)
    elif tamper == "root_attrs":
        after["entries"][1] = entry(
            LINUX, uuid.UUID(int=3), ROOT_FIRST, ROOT_LAST - 1, attrs=1
        )
    elif tamper == "root_name":
        after["entries"][1] = entry(
            LINUX, uuid.UUID(int=3), ROOT_FIRST, ROOT_LAST - 1, "OTHER"
        )
    elif tamper == "zero_root_guid":
        after["entries"][1] = entry(LINUX, uuid.UUID(int=0), ROOT_FIRST, ROOT_LAST - 1)
    elif tamper == "unknown_field":
        after["unvalidated"] = True
    with pytest.raises(GptRefusal):
        reconcile_linux_only(before, after)


def test_runner_binds_host_gpt_partuuid_to_guest_boot_proof():
    runner = (
        ROOT / "auto_tests/tools/gaslux_popos_native_full_firstboot_vm.sh"
    ).read_text(encoding="utf-8")
    assert "gaslux_popos_native_gpt_reconcile.py" in runner
    assert '"$work/owned-gpt-before.json"' in runner
    assert '"$work/owned-gpt-after.json"' in runner
    assert "GASLUX_POP_NATIVE_LINUXONLY_GPT_VERIFIED=1" in runner
    assert "rootPartuuidAfter" in runner
    assert "GASLUX_POP_NATIVE_FIRSTBOOT_ROOT_PARTUUID=$expected_partuuid" in runner
    assert "GASLUX_POP_NATIVE_FIRSTBOOT_WITHOUT_LIVE_ISO=1" in runner


def test_module_has_no_host_disk_writer():
    source = (
        ROOT / "auto_tests/tools/gaslux_popos_native_gpt_reconcile.py"
    ).read_text(encoding="utf-8")
    assert "subprocess" not in source
    assert "os.system" not in source
    assert 'image.open("rb")' in source
    assert '"productionInstallationAuthorized": False' in source
