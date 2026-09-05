#!/usr/bin/python3
"""Bounded, guest-local ARR configuration. Invoked only by deploy.

Native package layout was checked against community-scripts/ProxmoxVE
9996ed71ba50500b7156cfcf2ef519415d9e0187 (MIT); no installer code is executed.
API schemas come from the installed, release-pinned applications.
"""

import argparse
import base64
import configparser
from contextlib import contextmanager
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET


STATE = Path("/var/lib/arr")
MEDIA = STATE / "downloads"
APPS = (("sonarr", 8989, "v3", "tv", "tvCategory"),
        ("radarr", 7878, "v3", "movies", "movieCategory"),
        ("lidarr", 8686, "v1", "music", "musicCategory"),
        ("prowlarr", 9696, "v1", None, None))
# These identities are part of the pinned appliance image contract. Do not
# inherit ownership from retained configuration: that could redirect newly
# generated API credentials to an arbitrary account.
CONFIG_OWNERS = {
    "sonarr": (2200, 2200),
    "radarr": (2201, 2200),
    "lidarr": (2202, 2200),
    "prowlarr": (2204, 2200),
    "qbittorrent": (2205, 2200),
}


class ConfigurationError(Exception):
    """Only fixed, credential-free diagnostics may cross the process boundary."""


def check_path(path):
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ConfigurationError("configuration path contains a symlink")
    if path.exists() and not path.is_file():
        raise ConfigurationError("configuration path is not a regular file")


@contextmanager
def parent_directory(path):
    """Pin each directory without following a service-controlled symlink."""
    if not path.is_absolute():
        raise ConfigurationError("configuration path must be absolute")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        yield fd
    finally:
        os.close(fd)


def read_config(path):
    check_path(path)
    with parent_directory(path) as directory:
        try:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        except FileNotFoundError:
            return None, None
        with os.fdopen(fd) as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
                raise ConfigurationError("application configuration is not a bounded regular file")
            return source.read(1024 * 1024 + 1), info


def validate_config_owner(info, owner):
    if info is not None and (info.st_uid, info.st_gid) != owner:
        raise ConfigurationError("application configuration has an unexpected owner")


def write_config(path, content, owner):
    check_path(path)
    with parent_directory(path) as directory:
        try:
            existing = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
            if not stat.S_ISREG(existing.st_mode):
                raise ConfigurationError("application configuration is not a regular file")
            validate_config_owner(existing, owner)
        except FileNotFoundError:
            pass
        temporary = ".boetticher-" + secrets.token_hex(16)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory)
        try:
            with os.fdopen(fd, "w") as out:
                if os.geteuid() == 0:
                    os.fchown(out.fileno(), *owner)
                out.write(content)
                out.flush()
                os.fsync(out.fileno())
            os.replace(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        finally:
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass


def configure_xml(path, port, apply, owner):
    content, info = read_config(path)
    validate_config_owner(info, owner)
    root = ET.fromstring(content) if content is not None else ET.Element("Config")
    if root.tag != "Config":
        raise ConfigurationError("application configuration has an unexpected root")
    desired = {"BindAddress": "127.0.0.1", "Port": str(port), "EnableSsl": "False",
               "LaunchBrowser": "False", "AuthenticationMethod": "None",
               "AuthenticationRequired": "DisabledForLocalAddresses", "UrlBase": "",
               "UpdateAutomatically": "False", "UpdateMechanism": "External"}
    changed = info is None or stat.S_IMODE(info.st_mode) != 0o600
    for key, value in desired.items():
        elements = root.findall(key)
        if len(elements) > 1:
            raise ConfigurationError("duplicate application configuration field")
        element = elements[0] if elements else ET.SubElement(root, key)
        if not elements or (element.text or "") != value:
            element.text = value
            changed = True
    if not root.findtext("ApiKey"):
        changed = True
        if apply:
            element = root.find("ApiKey")
            if element is None:
                element = ET.SubElement(root, "ApiKey")
            element.text = secrets.token_hex(16)
    if changed and apply:
        write_config(path, ET.tostring(root, encoding="unicode") + "\n", owner)
    return changed


def configure_qbit(path, domain, apply, owner, peer_port=0):
    content, info = read_config(path)
    validate_config_owner(info, owner)
    config = configparser.ConfigParser(interpolation=None, delimiters=("=",), strict=True)
    config.optionxform = str
    if content is not None:
        config.read_string(content)
    desired = {
        "LegalNotice": {"Accepted": "true"},
        "Preferences": {
            "WebUI\\Address": "127.0.0.1", "WebUI\\Port": "8080",
            "WebUI\\LocalHostAuth": "false", "WebUI\\AuthSubnetWhitelistEnabled": "false",
            "WebUI\\CSRFProtection": "true", "WebUI\\HostHeaderValidation": "true",
            "WebUI\\ServerDomains": "qbittorrent." + domain,
            "WebUI\\UseUPnP": "false", "WebUI\\HTTPS\\Enabled": "false",
            "WebUI\\ReverseProxySupportEnabled": "false"},
        "BitTorrent": {"Session\\LSDEnabled": "false",
                      "Session\\Port": str(peer_port or 6881),
                      "Session\\Interface": "eth0", "Session\\InterfaceAddress": "10.10.20.110"},
        "Network": {"PortForwardingEnabled": "false"}}
    changed = info is None or stat.S_IMODE(info.st_mode) != 0o600
    for section, values in desired.items():
        if not config.has_section(section):
            config.add_section(section)
        for key, value in values.items():
            if config.get(section, key, fallback=None) != value:
                config.set(section, key, value)
                changed = True
    # Prevent qBittorrent generating and logging a temporary plaintext password.
    # Browser access is through operator mTLS; loopback clients need no password.
    if not config.get("Preferences", "WebUI\\Password_PBKDF2", fallback=""):
        changed = True
        if apply:
            salt = secrets.token_bytes(16)
            digest = hashlib.pbkdf2_hmac("sha512", secrets.token_bytes(32), salt, 100000)
            encoded = base64.b64encode(salt).decode() + ":" + base64.b64encode(digest).decode()
            config.set("Preferences", "WebUI\\Password_PBKDF2", "@ByteArray(" + encoded + ")")
    if changed and apply:
        out = io.StringIO()
        config.write(out, space_around_delimiters=False)
        write_config(path, out.getvalue(), owner)
    return changed


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ConfigurationError("application redirected a local API request")


class API:
    def __init__(self, name, port, prefix, key=None):
        self.name, self.base, self.key = name, f"http://127.0.0.1:{port}/api/{prefix}/", key
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(self, method, path, data=None):
        headers = {"Referer": self.base, "Accept": "application/json"}
        if self.key:
            headers["X-Api-Key"] = self.key
        body = None
        if data is not None:
            if self.name == "qbittorrent":
                body = urllib.parse.urlencode(data).encode()
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            else:
                body = json.dumps(data).encode()
                headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.base + path, data=body, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=5) as response:
                raw = response.read(4 * 1024 * 1024 + 1)
                if len(raw) > 4 * 1024 * 1024:
                    raise ConfigurationError("application API response is too large")
                return json.loads(raw) if raw and raw[:1] in (b"{", b"[") else raw.decode()
        except urllib.error.HTTPError as error:
            raise ConfigurationError(f"{self.name} API rejected request (HTTP {error.code})") from None
        except (ValueError, UnicodeError, urllib.error.URLError, TimeoutError):
            raise ConfigurationError(f"{self.name} API unavailable or invalid response") from None

    def ready(self, path):
        for attempt in range(30):
            try:
                result = self.request("GET", path)
                if not isinstance(result, dict):
                    raise ConfigurationError("application readiness response is invalid")
                return
            except ConfigurationError:
                if attempt == 29:
                    raise
                time.sleep(1)


def fields(record):
    return {field["name"]: field.get("value") for field in record.get("fields", [])}


def connection(api, resource, implementation, name, values, properties):
    records = api.request("GET", resource)
    owned = [record for record in records if record.get("name") == name]
    if len(owned) > 1:
        raise ConfigurationError("duplicate Boetticher application connections")
    for record in records:
        if record.get("name") == name:
            continue
        current = fields(record)
        if record.get("implementation") == implementation and (
                current.get("host") in ("localhost", "127.0.0.1") or
                current.get("baseUrl", "").rstrip("/") == values.get("baseUrl")):
            raise ConfigurationError("existing local application connection needs operator resolution")
    if owned:
        record = copy.deepcopy(owned[0])
        if record.get("implementation") != implementation:
            raise ConfigurationError("Boetticher connection has an unexpected implementation")
    else:
        schemas = [s for s in api.request("GET", resource + "/schema")
                   if s.get("implementation") == implementation]
        if len(schemas) != 1:
            raise ConfigurationError("installed application API schema is unsupported")
        record = copy.deepcopy(schemas[0])
        record.pop("id", None)
        record["name"] = name
    if not set(values).issubset(fields(record)):
        raise ConfigurationError("installed application API fields are unsupported")
    changed = not owned or any(record.get(k) != v for k, v in properties.items())
    record.update(properties)
    masked = []
    for field in record["fields"]:
        if field["name"] in values:
            value = values[field["name"]]
            if owned and field.get("value") == "********":
                masked.append(field)
                continue
            changed |= field.get("value") != value
            field["value"] = value
    if masked:
        # Prowlarr deliberately masks stored API keys. Its test endpoint resolves
        # the mask against the existing record without persisting changes. A
        # successful test proves the retained credential still works; a failed
        # test retries with the current guest-local key through normal validation.
        try:
            api.request("POST", resource + "/test", record)
        except ConfigurationError:
            for field in masked:
                field["value"] = values[field["name"]]
            changed = True
    if changed:
        api.request("PUT" if owned else "POST",
                    resource + ("/" + str(record["id"]) if owned else ""), record)
    return changed


def settings(api, resource, desired):
    current = api.request("GET", resource)
    if not set(desired).issubset(current):
        raise ConfigurationError("installed application settings are unsupported")
    if all(current[k] == v for k, v in desired.items()):
        return False
    current.update(desired)
    api.request("PUT", resource, current)
    return True


def wire():
    clients = {}
    for name, port, version, _, _ in APPS:
        path = STATE / name / "config.xml"
        content, _ = read_config(path)
        key = ET.fromstring(content or "<Config/>").findtext("ApiKey")
        if not key:
            raise ConfigurationError("application API identity is missing")
        client = API(name, port, version, key)
        client.ready("system/status")
        clients[name] = client
    qbit = API("qbittorrent", 8080, "v2")
    qbit.ready("app/preferences")
    categories = qbit.request("GET", "torrents/categories")
    changed = False
    for name, port, _, library, category_field in APPS[:3]:
        category = "boetticher-" + library
        destination = str(MEDIA / "incoming" / library)
        if category not in categories:
            qbit.request("POST", "torrents/createCategory", {"category": category, "savePath": destination})
            changed = True
        elif categories[category].get("savePath") != destination:
            qbit.request("POST", "torrents/editCategory", {"category": category, "savePath": destination})
            changed = True
        client = clients[name]
        changed |= connection(client, "downloadclient", "QBittorrent", "boetticher-qbittorrent",
                              {"host": "127.0.0.1", "port": 8080, "useSsl": False,
                               category_field: category}, {"enable": True})
        changed |= connection(clients["prowlarr"], "applications", name.title(), "boetticher-" + name,
                              {"baseUrl": f"http://127.0.0.1:{port}",
                               "prowlarrUrl": "http://127.0.0.1:9696", "apiKey": client.key},
                              {"syncLevel": "fullSync"})
        changed |= settings(client, "config/downloadclient", {"enableCompletedDownloadHandling": True})
        changed |= settings(client, "config/mediamanagement", {"copyUsingHardlinks": True})
        roots = client.request("GET", "rootfolder")
        path = str(MEDIA / "library" / library)
        matches = [r for r in roots if r.get("path", "").rstrip("/") == path]
        if len(matches) > 1:
            raise ConfigurationError("duplicate media root folders")
        if not matches:
            root = {"path": path}
            if name == "lidarr":
                # Use the oldest existing upstream profile only for this new root;
                # never modify profiles or defaults on retained roots.
                root.update(name="Boetticher music", defaultMonitorOption="all",
                            defaultNewItemMonitorOption="all", defaultTags=[])
                for endpoint, field in (("qualityprofile", "defaultQualityProfileId"),
                                        ("metadataprofile", "defaultMetadataProfileId")):
                    profiles = client.request("GET", endpoint)
                    if not profiles:
                        raise ConfigurationError("Lidarr requires an existing default profile")
                    root[field] = min(p["id"] for p in profiles)
            client.request("POST", "rootfolder", root)
            changed = True
    return changed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("check", "prepare", "wire"))
    parser.add_argument("--domain", default="")
    parser.add_argument("--peer-port", type=int, default=0)
    args = parser.parse_args()
    try:
        if args.peer_port in (7878, 8080, 8686, 8989, 9696) or (args.peer_port != 0 and not 2049 <= args.peer_port <= 65535):
            raise ConfigurationError("invalid AirVPN reserved peer port")
        if args.mode == "wire":
            changed = wire()
        else:
            if not args.domain or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789.-" for c in args.domain):
                raise ConfigurationError("invalid ARR frontend domain")
            changed = False
            for name, port, _, _, _ in APPS:
                changed |= configure_xml(STATE / name / "config.xml", port, args.mode == "prepare", CONFIG_OWNERS[name])
            changed |= configure_qbit(STATE / "qbittorrent/qBittorrent/config/qBittorrent.conf",
                                      args.domain, args.mode == "prepare", CONFIG_OWNERS["qbittorrent"], args.peer_port)
        print("changed" if changed else "unchanged")
    except (ConfigurationError, OSError, ValueError, KeyError, TypeError, ET.ParseError, configparser.Error) as error:
        message = str(error) if isinstance(error, ConfigurationError) else "invalid or inaccessible application state"
        print("FAIL: ARR configuration: " + message, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
