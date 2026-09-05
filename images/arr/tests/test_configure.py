import copy
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.error


spec = importlib.util.spec_from_file_location(
    "arr", Path(__file__).parents[1] / "runtime" / "configure.py")
arr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(arr)
TEST_OWNER = (os.getuid(), os.getgid())


class API:
    def __init__(self, records=None):
        self.records = records or []
        self.writes = []

    def request(self, method, path, data=None):
        if method == "GET":
            if path.endswith("/schema"):
                return [{"implementation": "QBittorrent", "configContract": "QBittorrentSettings",
                         "fields": [{"name": "host", "value": "localhost"},
                                    {"name": "tvCategory", "value": "tv-sonarr"}]}]
            return copy.deepcopy(self.records)
        self.writes.append((method, path, copy.deepcopy(data)))
        if method == "POST":
            data = dict(data, id=len(self.records) + 1)
            self.records.append(data)
        else:
            self.records = [data if r["id"] == data["id"] else r for r in self.records]
        return data


class ReconcileTests(unittest.TestCase):
    def test_masked_key_is_tested_without_rewriting_and_rotation_is_repaired(self):
        record = {"id": 1, "name": "boetticher-sonarr", "implementation": "Sonarr",
                  "fields": [{"name": "apiKey", "value": "********"}]}
        for rejected in (False, True):
            api = API([copy.deepcopy(record)])
            original = api.request
            tests = []
            def test_request(method, path, data=None):
                if path == "applications/test":
                    tests.append(copy.deepcopy(data))
                    if rejected:
                        raise arr.ConfigurationError("old key rejected")
                    return {}
                return original(method, path, data)
            with patch.object(api, "request", side_effect=test_request):
                changed = arr.connection(api, "applications", "Sonarr", "boetticher-sonarr",
                                         {"apiKey": "test-only-new-key"}, {})
            self.assertEqual(changed, rejected)
            self.assertEqual(tests[0]["fields"][0]["value"], "********")
            self.assertEqual(len(api.writes), int(rejected))
            if rejected:
                self.assertEqual(api.writes[0][0], "PUT")
                self.assertEqual(api.writes[0][2]["fields"][0]["value"], "test-only-new-key")

    def test_qbit_port_security_and_existing_state_survive_redeploy(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp).resolve() / "qBittorrent.conf"
            path.write_text("[Preferences]\nWebUI\\Password_PBKDF2=@ByteArray(test-only-hash)\n"
                            "[BitTorrent]\nSession\\GlobalDLSpeedLimit=123\n")
            self.assertTrue(arr.configure_qbit(path, "example.test", True, TEST_OWNER, 45678))
            self.assertFalse(arr.configure_qbit(path, "example.test", False, TEST_OWNER, 45678))
            self.assertIn("PortForwardingEnabled=false", path.read_text())
            self.assertIn("Session\\Port=45678", path.read_text())
            self.assertIn("WebUI\\LocalHostAuth=false", path.read_text())
            self.assertIn("WebUI\\CSRFProtection=true", path.read_text())
            self.assertIn("test-only-hash", path.read_text())
            self.assertIn("Session\\GlobalDLSpeedLimit=123", path.read_text())

    def test_api_errors_do_not_disclose_response_or_credentials(self):
        api = arr.API("sonarr", 8989, "v3", "test-only-secret")
        error = urllib.error.HTTPError("http://127.0.0.1/", 401, "test-only-secret", {}, None)
        with patch.object(api.opener, "open", side_effect=error):
            with self.assertRaises(arr.ConfigurationError) as raised:
                api.request("GET", "system/status")
        self.assertEqual(str(raised.exception), "sonarr API rejected request (HTTP 401)")

    def test_redirects_cannot_forward_api_credentials(self):
        with self.assertRaises(arr.ConfigurationError):
            arr.NoRedirect().redirect_request(None, None, 302, "", {}, "https://outside.test")

    def test_readiness_retries_are_bounded(self):
        api = arr.API("sonarr", 8989, "v3")
        with patch.object(api, "request", side_effect=arr.ConfigurationError("unavailable")) as request:
            with patch.object(arr.time, "sleep"):
                with self.assertRaises(arr.ConfigurationError):
                    api.ready("system/status")
        self.assertEqual(request.call_count, 30)

    def test_owned_record_can_retry_after_failed_mutation(self):
        api = API()
        original = api.request
        def fail_post(method, path, data=None):
            if method == "POST":
                # Simulate a lost response after the server committed its write.
                original(method, path, data)
                raise arr.ConfigurationError("connection lost")
            return original(method, path, data)
        args = (api, "downloadclient", "QBittorrent", "boetticher-qbittorrent",
                {"host": "127.0.0.1"}, {"enable": True})
        with patch.object(api, "request", side_effect=fail_post):
            with self.assertRaises(arr.ConfigurationError):
                arr.connection(*args)
        self.assertFalse(arr.connection(*args))
        self.assertEqual(len(api.records), 1)

    def test_connection_is_idempotent_and_preserves_operator_fields(self):
        api = API()
        args = (api, "downloadclient", "QBittorrent", "boetticher-qbittorrent",
                {"host": "127.0.0.1", "tvCategory": "boetticher-tv"}, {"enable": True})
        self.assertTrue(arr.connection(*args))
        api.records[0]["priority"] = 17
        self.assertFalse(arr.connection(*args))
        api.records[0]["fields"][0]["value"] = "wrong-host"
        self.assertTrue(arr.connection(*args))
        self.assertEqual(api.records[0]["priority"], 17)
        self.assertEqual(len(api.records), 1)

    def test_ambiguous_or_unowned_connection_is_not_adopted(self):
        for records in ([{"name": "personal", "implementation": "QBittorrent",
                          "fields": [{"name": "host", "value": "localhost"}]}],
                        [{"name": "boetticher-qbittorrent"}] * 2):
            api = API(records)
            with self.assertRaises(arr.ConfigurationError):
                arr.connection(api, "downloadclient", "QBittorrent", "boetticher-qbittorrent",
                               {"host": "127.0.0.1", "tvCategory": "boetticher-tv"}, {})
            self.assertEqual(api.writes, [])

    def test_incompatible_schema_fails_without_write(self):
        api = API()
        with self.assertRaises(arr.ConfigurationError):
            arr.connection(api, "downloadclient", "QBittorrent", "boetticher-qbittorrent",
                           {"nonexistent": True}, {})
        self.assertEqual(api.writes, [])

    def test_configuration_preserves_api_key_and_enforces_loopback(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp).resolve() / "config.xml"
            path.write_text("<Config><ApiKey>test-only-key</ApiKey><BindAddress>*</BindAddress>"
                            "<Unrelated>keep</Unrelated></Config>")
            self.assertTrue(arr.configure_xml(path, 8989, False, TEST_OWNER))
            self.assertIn("<BindAddress>*</BindAddress>", path.read_text())
            self.assertTrue(arr.configure_xml(path, 8989, True, TEST_OWNER))
            self.assertFalse(arr.configure_xml(path, 8989, False, TEST_OWNER))
            self.assertIn("test-only-key", path.read_text())
            self.assertIn("<Unrelated>keep</Unrelated>", path.read_text())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_configuration_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / "target").write_text("<Config/>")
            (root / "config.xml").symlink_to(root / "target")
            with self.assertRaises(arr.ConfigurationError):
                arr.configure_xml(root / "config.xml", 8989, True, TEST_OWNER)

    def test_atomic_failure_preserves_original_and_removes_staging(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            path = root / "config.xml"
            path.write_text("<Config><ApiKey>test-only-key</ApiKey></Config>")
            original = path.read_bytes()
            with patch.object(arr.os, "replace", side_effect=OSError("write interrupted")):
                with self.assertRaises(OSError):
                    arr.configure_xml(path, 8989, True, TEST_OWNER)
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(list(root.iterdir()), [path])

    def test_directory_swap_cannot_redirect_atomic_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            directory = root / "app"
            directory.mkdir()
            outside = root / "outside"
            outside.mkdir()
            (outside / "config.xml").write_text("must not change")
            path = directory / "config.xml"
            path.write_text("<Config/>")
            replace = arr.os.replace
            def swap(source, target, **kwargs):
                directory.rename(root / "original")
                directory.symlink_to(outside, target_is_directory=True)
                return replace(source, target, **kwargs)
            with patch.object(arr.os, "replace", side_effect=swap):
                arr.configure_xml(path, 8989, True, TEST_OWNER)
            self.assertEqual((outside / "config.xml").read_text(), "must not change")
            self.assertIn("<BindAddress>127.0.0.1</BindAddress>",
                          (root / "original/config.xml").read_text())

    def test_existing_configuration_with_unexpected_owner_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp).resolve() / "config.xml"
            path.write_text("<Config/>")
            original = path.read_bytes()
            with self.assertRaises(arr.ConfigurationError):
                arr.configure_xml(path, 8989, False, (TEST_OWNER[0] + 1, TEST_OWNER[1]))
            self.assertEqual(path.read_bytes(), original)

    def test_qbit_configuration_with_unexpected_owner_is_rejected_without_rewrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp).resolve() / "qBittorrent.conf"
            path.write_text("[Preferences]\nWebUI\\Address=*\n")
            original = path.read_bytes()
            with self.assertRaises(arr.ConfigurationError):
                arr.configure_qbit(path, "example.test", True, (TEST_OWNER[0] + 1, TEST_OWNER[1]))
            self.assertEqual(path.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
