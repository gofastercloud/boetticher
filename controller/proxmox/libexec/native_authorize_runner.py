import importlib.machinery, io, json, os, subprocess, tempfile

mod = importlib.machinery.SourceFileLoader('auth', 'controller/proxmox/libexec/boetticher-authorize-controller-lab').load_module()
test = importlib.machinery.SourceFileLoader('fixture', 'controller/proxmox/libexec/test_authorize_controller_lab.py').load_module()
tempfile.tempdir = '/root'
fixture = test.HelperMain('runTest')
production_expected_mode = mod.expected_mode
fixture.setUp()
try:
    # Model Proxmox's cluster-managed root authorized_keys link separately;
    # the helper owns only its supplemental LAB file.
    os.makedirs('/etc/pve/priv', exist_ok=True); os.makedirs('/root/.ssh', exist_ok=True)
    cluster = '/etc/pve/priv/authorized_keys'
    home_link = '/root/.ssh/authorized_keys'
    supplemental = os.path.join(fixture.d.name, 'boetticher-controller-lab.authorized_keys')
    os.unlink(home_link) if os.path.lexists(home_link) else None
    os.unlink(cluster) if os.path.lexists(cluster) else None
    with open(cluster, 'w') as f: f.write('from="192.168.4.6",restrict ' + fixture.key + ' home\ncluster-key\n')
    os.symlink(cluster, home_link)
    os.chmod(cluster, 0o600); os.chown(cluster, 0, 33)
    os.unlink(supplemental) if os.path.lexists(supplemental) else None
    mod.PATHS['authorized_keys'] = supplemental; mod.PATHS['home_authorized_keys'] = home_link; mod.AK = supplemental; mod.HOMEAK = home_link; mod.HOME_TARGET = cluster; mod.HOME_TARGET_GID = 33
    mod.expected_mode = production_expected_mode
    with open(fixture.d.name + '/sshd_config', 'a') as f:
        f.write('AuthorizedKeysFile .ssh/authorized_keys .ssh/operator_keys\n')
    cluster_before = open(cluster, 'rb').read()
    real_run = mod.subprocess.run
    mod.subprocess.run = lambda args, **kw: subprocess.CompletedProcess(args, 0) if args[:3] == ['systemctl', 'reload', 'ssh'] else real_run(args, **kw)
    mod.sys.stdin = io.StringIO(json.dumps({'action':'apply','lab_address':'10.10.20.10','lab_mac':'6c:1f:f7:d2:5d:97','public_key':fixture.key}))
    try:
        mod.main()
    except Exception:
        for label, path in [('AK', mod.AK), ('DROP', mod.DROP)]:
            if os.path.exists(path):
                st = os.stat(path)
                print('diagnostic', label, path, st.st_uid, st.st_gid, oct(st.st_mode & 0o777), 'expected', mod.OWNER_UID, mod.OWNER_GID, oct(mod.expected_mode(path)))
        raise
    assert open(cluster, 'rb').read() == cluster_before
    assert os.path.exists(supplemental)
    mod.sys.stdin = io.StringIO(json.dumps({'action':'apply','lab_address':'10.10.20.10','lab_mac':'6c:1f:f7:d2:5d:97','public_key':fixture.key}))
    mod.main()
    print('native helper apply and idempotent retry PASS')
finally:
    fixture.tearDown()
