"""Adversarial read-only Anaconda D-Bus capture, not synthetic write-set approval."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "auto_tests"))

from bazzite_anaconda_readonly_capture import (  # noqa: E402
    BUS,
    SERVICE,
    CaptureRefusal,
    capture,
    installed_service,
    parse_device_ids,
    process_proof,
    viewer_from_xml,
)

XML = f"""<node><interface name="{SERVICE}.DeviceTreeViewer">
  <method name="GetActions"><arg type="aa{{sv}}" direction="out"/></method>
  <method name="GetDevices"><arg type="as" direction="out"/></method>
  <method name="GetDisks"><arg type="as" direction="out"/></method>
  <method name="GetMountPoints"><arg type="a{{ss}}" direction="out"/></method>
  <method name="GetBootDevice"><arg type="s" direction="out"/></method>
  <method name="GetDeviceData">
    <arg type="s" direction="in"/><arg type="a{{sv}}" direction="out"/>
  </method>
  <method name="GetFormatData">
    <arg type="s" direction="in"/><arg type="a{{sv}}" direction="out"/>
  </method>
  <method name="ApplyPartitioning"><arg type="o" direction="in"/></method>
  <method name="InstallWithTasks"/>
</interface></node>"""


def guest_reader(*, missing=None, replaced=False, bad_devices=False, xml=XML):
    calls = []
    ownership = 0

    def reader(*cmd):
        nonlocal ownership
        assert cmd[0:2] == (BUS, "--system")
        calls.append(cmd)
        if cmd[2] == "list":
            if missing == "service":
                return "org.freedesktop.DBus 1 ...\n"
            return f"{SERVICE} 432 anaconda root :1.37 -\n"
        if cmd[2] == "tree":
            return "/org/fedoraproject/Anaconda/Modules/Storage/DeviceTree\n"
        if cmd[2] == "introspect":
            return xml
        assert cmd[2] == "call"
        method = cmd[6]
        if method == "GetNameOwner":
            ownership += 1
            return 's ":1.38"\n' if replaced and ownership > 1 else 's ":1.37"\n'
        if method == "GetConnectionUnixProcessID":
            return "u 432\n"
        if method == "GetActions":
            return "aa{sv} 0\n"
        if method == "GetDevices":
            if missing == "truncated-devices":
                return 'as 2 "vda"\n'
            return 'as 2 "vda" "vda1"\n' if not bad_devices else 'as 2 "vda" "vda"\n'
        if method == "GetDisks":
            return 'as 1 "vda"\n'
        if method == "GetMountPoints":
            return "a{ss} 0\n"
        if method == "GetBootDevice":
            return 's ""\n'
        if method in ("GetDeviceData", "GetFormatData"):
            return "a{sv} 0\n"
        raise AssertionError(f"Unknown or mutating method attempted: {method}")

    return reader, calls


def verifier(pid):
    return {
        "pid": pid,
        "commandLine": "/usr/sbin/anaconda",
        "executablePath": "/usr/bin/python3",
        "executableSha256": "a" * 64,
    }


def test_reads_only_existing_service_from_unique_owner_and_never_authorizes():
    reader, calls = guest_reader()
    result = capture(reader, verifier)
    assert result["origin"] == "anaconda-dbus-readonly-untrusted"
    assert result["uniqueOwner"] == ":1.37"
    assert result["deviceIds"] == ["vda", "vda1"]
    assert result["rawResponses"]["GetActions"] == "aa{sv} 0\n"
    assert len(result["rawResponses"]["GetFormatData"]) == 2
    assert result["realActionGraphAuthenticated"] is False
    assert result["hostIsoAndQemuBindingVerified"] is False
    assert result["nativeInstallerWriteSetVerified"] is False
    for key in (
        "installationAuthorized", "partitionWriteAuthorized",
        "gptMetadataWriteAuthorized", "windowsEspWriteAuthorized",
        "nvramWriteAuthorized",
    ):
        assert result[key] is False
    assert all(
        not {"ApplyPartitioning", "InstallWithTasks", "CreatePartitioning",
             "Format", "mkfs", "ResetPartitioning"}.intersection(set(cmd))
        for cmd in calls
    )
    assert all(
        cmd[3] in (":1.37", "org.freedesktop.DBus")
        for cmd in calls if cmd[2] == "call"
    )


@pytest.mark.parametrize("problem", ("service", "truncated-devices"))
def test_missing_service_or_unparseable_devices_refused(problem):
    reader, _ = guest_reader(missing=problem)
    with pytest.raises(CaptureRefusal):
        capture(reader, verifier)


def test_replaced_service_refused_even_if_initial_observation_valid():
    reader, _ = guest_reader(replaced=True)
    with pytest.raises(CaptureRefusal, match="replaced"):
        capture(reader, verifier)


def test_duplicate_guest_devices_refused():
    reader, _ = guest_reader(bad_devices=True)
    with pytest.raises(CaptureRefusal, match="Duplicate"):
        capture(reader, verifier)


@pytest.mark.parametrize(
    "broken",
    [
        "<node/>",
        "<node><interface name='other'><method name='GetActions'/></interface></node>",
        XML.replace('name="GetActions"', 'name="GetActionList"'),
        XML + "<node/>",
        "<node><interface",
    ],
)
def test_unknown_or_broken_viewer_interface_refused(broken):
    with pytest.raises(CaptureRefusal):
        viewer_from_xml(broken)


def test_getactions_read_signature_must_have_no_inputs():
    xml = XML.replace(
        '<method name="GetActions"><arg type="aa{sv}" direction="out"/></method>',
        '<method name="GetActions"><arg type="s" direction="in"/></method>',
    )
    with pytest.raises(CaptureRefusal, match="GetActions"):
        viewer_from_xml(xml)


def test_missing_optional_interfaces_are_not_conjured():
    xml = XML.replace(
        '<method name="GetBootDevice"><arg type="s" direction="out"/></method>', ""
    )
    reader, calls = guest_reader(xml=xml)
    report = capture(reader, verifier)
    assert report["unobservedMethods"] == ["GetBootDevice"]
    assert "GetBootDevice" not in report["rawResponses"]
    assert not any("GetBootDevice" in cmd for cmd in calls)


def test_bogus_installer_binary_proof_refused():
    reader, _ = guest_reader()
    with pytest.raises(CaptureRefusal, match="Executable"):
        capture(reader, lambda pid: {"pid": pid, "executableSha256": "wrong"})
    with pytest.raises(CaptureRefusal, match="Executable"):
        capture(reader, lambda pid: {"pid": pid + 1, "executableSha256": "a" * 64})


def test_proc_rejects_invalid_pid_before_read():
    with pytest.raises(CaptureRefusal, match="Invalid"):
        process_proof(0)
    with pytest.raises(CaptureRefusal, match="Invalid"):
        process_proof(True)


def test_list_requires_exact_name_not_substring_or_prefix():
    assert installed_service(f"{SERVICE}.Fake 1337 bad\n") is False
    assert installed_service(f"{SERVICE} 1422 python\n") is True


@pytest.mark.parametrize(
    "value",
    [
        "as 65 " + " ".join(f'"dev{i}"' for i in range(65)),
        'as 2 "a"\n',
        'as 1 "/dev/evil;mkfs"\n',
        "aa{sv} 0\n",
        "as -1\n",
    ],
)
def test_adversarial_device_lists_refused(value):
    with pytest.raises(CaptureRefusal):
        parse_device_ids(value)


def test_capture_does_not_verify_payload_geometry_esp_or_atomic_deployment():
    reader, _ = guest_reader()
    report = capture(reader, verifier)
    for name in (
        "gptPrimaryAndBackupWritesObserved", "efiWritesObserved",
        "nvramOperationsObserved", "atomicPayloadBoundToIso",
    ):
        assert report[name] is False
    assert "diskGuid" not in report
    assert "payloadDigest" not in report
