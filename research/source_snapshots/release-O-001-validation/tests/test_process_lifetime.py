import subprocess
import unittest
from unittest.mock import Mock,patch

from kryptos.process_lifetime import _PosixProcess


class PosixLifetimeTests(unittest.TestCase):
    def process(self):
        child=Mock(pid=987654,returncode=0)
        with patch("kryptos.process_lifetime.subprocess.Popen",return_value=child):
            owned=_PosixProcess(["mock-worker"],None,None,subprocess.DEVNULL,subprocess.DEVNULL,subprocess.DEVNULL)
        return owned,child

    def test_repeated_close_and_signals_after_close_are_noops(self):
        owned,child=self.process()
        with patch("kryptos.process_lifetime.os.killpg",create=True) as kill_group,patch("kryptos.process_lifetime.signal.SIGKILL",9,create=True):
            owned.close()
            owned.close()
            owned.terminate()
            owned.kill()
        kill_group.assert_called_once_with(child.pid,9)
        child.wait.assert_called_once_with(timeout=3)

    def test_failed_wait_leaves_cleanup_retryable(self):
        owned,child=self.process()
        child.wait.side_effect=[subprocess.TimeoutExpired("mock-worker",3),0]
        with patch("kryptos.process_lifetime.os.killpg",create=True) as kill_group,patch("kryptos.process_lifetime.signal.SIGKILL",9,create=True):
            with self.assertRaises(subprocess.TimeoutExpired):
                owned.close()
            owned.close()
            owned.close()
        self.assertEqual(kill_group.call_count,2)
        self.assertEqual(child.wait.call_count,2)


if __name__=="__main__":
    unittest.main()
