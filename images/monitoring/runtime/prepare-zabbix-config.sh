#!/bin/sh
set -eu

credential=/run/credentials/zabbix-server.service/zabbix-db-password
template=/etc/zabbix/zabbix_server.conf.template
runtime=/run/zabbix/zabbix_server.conf
test -r "$credential"
test -r "$template"

python3 - "$credential" "$template" "$runtime" <<'PY'
import os
import pathlib
import subprocess
import sys

credential, template, runtime = map(pathlib.Path, sys.argv[1:])
password = credential.read_text()
if not password or "\n" in password.rstrip("\n") or "\r" in password:
    raise SystemExit("zabbix credential must be a single line")
password = password.rstrip("\n")

def sql_quote(value):
    return "'" + value.replace("'", "''") + "'"

subprocess.run(
    ["runuser", "-u", "postgres", "--", "psql", "--dbname", "postgres", "--set", "ON_ERROR_STOP=1"],
    input=("ALTER ROLE zabbix LOGIN PASSWORD " + sql_quote(password) + ";\n").encode(),
    check=True,
)

lines = [line for line in template.read_text().splitlines() if not line.startswith("DBPassword=")]
lines.append("DBPassword=" + password)
temporary = runtime.with_name(runtime.name + ".new")
temporary.write_text("\n".join(lines) + "\n")
os.chown(temporary, 0, __import__("grp").getgrnam("zabbix").gr_gid)
os.chmod(temporary, 0o640)
os.replace(temporary, runtime)
PY
