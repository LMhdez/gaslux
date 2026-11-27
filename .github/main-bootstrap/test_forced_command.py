import unittest
from unittest.mock import patch
import forced_command as f

class ForcedCommandTests(unittest.TestCase):
    def test_witness_roles_fixed(self):
        for role,expected in (("witness-signer","signer"),("witness-publisher","publisher")):
            with patch.object(f.sys,"argv",["forced_command.py",role]), \
                 patch.dict(f.os.environ,{"SSH_ORIGINAL_COMMAND":"gaslux-witness-v1"},clear=True), \
                 patch.object(f.os,"chdir"),patch.object(f.os,"umask"),patch.object(f.os,"execve") as run:
                f.main()
                self.assertEqual(run.call_args.args[1][-2:],[expected,"serve"])
    def test_shell_init_sign_or_cross_role_rejected(self):
        for role,command in (("safety","sign"),("safety","gaslux-witness-v1"),
                             ("witness-signer","gaslux-witness-v1; sh"),
                             ("witness-publisher","init"),("unknown","gaslux-safety-feed-v1")):
            with patch.object(f.sys,"argv",["forced_command.py",role]), \
                 patch.dict(f.os.environ,{"SSH_ORIGINAL_COMMAND":command},clear=True), \
                 patch.object(f.os,"execve") as run:
                with self.assertRaises(SystemExit): f.main()
                run.assert_not_called()
