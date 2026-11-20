"""Real local subprocess contracts: socket FD inheriting versus close_fds."""

from auto_tests.installer_observer.fd_audit import audit_child_fds


def test_synthetic_unix_socket_fd_inheritance_is_explicitly_closed():
    result = audit_child_fds()
    assert result["synthetic_inheritable_fd_positive_control"] is True
    assert result["close_fds_excludes_inheritable_socket"] is True
    assert result["guest_input_emitted"] is False
