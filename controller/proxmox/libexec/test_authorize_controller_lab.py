import importlib.machinery, os, tempfile, unittest, io, json, fcntl
from unittest.mock import patch

mod=importlib.machinery.SourceFileLoader('auth','controller/proxmox/libexec/boetticher-authorize-controller-lab').load_module()

class SafeIO(unittest.TestCase):
 def setUp(self):
  self.old=(mod.AK,mod.MAIN,mod.DROP,mod.OWNER_GID)
  self.d=tempfile.TemporaryDirectory(); self.uid=os.getuid(); self.p=os.path.join(self.d.name,'x')
  with open(self.p,'wb') as f: f.write(b'old')
  os.chmod(self.p,0o600); os.chown(self.p,os.getuid(),os.getgid()); mod.AK=self.p; mod.OWNER_GID=os.getgid()
 def tearDown(self): mod.AK,mod.MAIN,mod.DROP,mod.OWNER_GID=self.old; self.d.cleanup()
 def test_atomic_and_freshness(self):
  s=mod.snapshot(self.p,self.uid); mod.atomic(self.p,b'new',0o600,s,self.uid); self.assertEqual(mod.snapshot(self.p,self.uid)[5],b'new')
  s=mod.snapshot(self.p,self.uid)
  with open(self.p,'wb') as f: f.write(b'race')
  with self.assertRaises(RuntimeError): mod.atomic(self.p,b'x',0o600,s,self.uid)
 def test_symlink_refused(self):
  target=os.path.join(self.d.name,'target')
  with open(target,'w') as f: f.write('x')
  link=os.path.join(self.d.name,'link'); os.symlink(target,link)
  with self.assertRaises((OSError,RuntimeError)): mod.snapshot(link,self.uid)
 def test_writable_mode_refused(self):
  os.chmod(self.p,0o666)
  with self.assertRaises(RuntimeError): mod.snapshot(self.p,self.uid)

class HelperMain(unittest.TestCase):
 def contents(self):
  result=[]
  for x in mod.PATHS:
   if os.path.exists(mod.PATHS[x]):
    with open(mod.PATHS[x],'rb') as f: result.append(f.read())
   else: result.append(None)
  return result
 def setUp(self):
  self.d=tempfile.TemporaryDirectory(); self.old=(mod.PATHS.copy(),mod.OWNER_UID,mod.OWNER_GID,mod.TMPROOT,mod.LOCKPATH,mod.expected_mode)
  ak=os.path.join(self.d.name,'authorized_keys'); main=os.path.join(self.d.name,'sshd_config'); drop=os.path.join(self.d.name,'drop')
  key='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
  with open(ak,'w') as f: f.write('from="192.168.4.6",restrict '+key+' home\nunrelated ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n')
  with open(main,'w') as f: f.write('Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\n')
  os.chmod(ak,0o600); os.chmod(main,0o644); os.chown(ak,os.getuid(),os.getgid()); os.chown(main,os.getuid(),os.getgid()); mod.PATHS={'authorized_keys':ak,'main':main,'drop':drop}; mod.AK,mod.MAIN,mod.DROP=ak,main,drop; mod.expected_mode=lambda path: 0o600 if path in (ak,drop) else 0o644; mod.OWNER_UID=os.getuid(); mod.OWNER_GID=os.getgid(); mod.TMPROOT=self.d.name; mod.LOCKPATH=os.path.join(self.d.name,'lock'); self.key=key
 def tearDown(self): mod.PATHS,mod.OWNER_UID,mod.OWNER_GID,mod.TMPROOT,mod.LOCKPATH,mod.expected_mode=self.old; self.d.cleanup()
 def call(self,action,fail=False,mismatch=False,reloadfail=False,keyfail=False,extra=False,baseline=None):
  req={'action':action,'lab_address':'10.10.20.10','lab_mac':'6c:1f:f7:d2:5d:97','public_key':self.key}; before=self.contents()
  calls=[]
  reloads=[0]
  def run(args,**kw):
   calls.append(args)
   if args[:3]==['systemctl','reload','ssh']:
    reloads[0]+=1
    if reloadfail and reloads[0]==1: raise mod.subprocess.CalledProcessError(1,args)
   if fail and args[:2]==['sshd','-t']: raise mod.subprocess.CalledProcessError(1,args)
   return None
  seen=[0]
  def out(args,**kw):
   seen[0]+=1
   lab='10.10.20.10' in ' '.join(map(str,args))
   if baseline is not None and not lab: return 'authorizedkeysfile '+baseline+'\nallowtcpforwarding yes\n'
   if extra and lab: return f'authorizedkeysfile .ssh/authorized_keys {mod.AK}\nallowtcpforwarding local\npermitopen 10.10.99.1:443 10.10.99.2:444\npermitlisten none\nallowstreamlocalforwarding no\nx11forwarding no\nallowagentforwarding no\n'
   if mismatch and seen[0] > 2 and lab: return f'authorizedkeysfile .ssh/authorized_keys {mod.AK}\nallowtcpforwarding yes\n'
   return f'authorizedkeysfile .ssh/authorized_keys {mod.AK}\nallowtcpforwarding local\npermitopen 10.10.99.1:443\npermitlisten none\nallowstreamlocalforwarding no\nx11forwarding no\nallowagentforwarding no\n' if lab else 'authorizedkeysfile .ssh/authorized_keys\nallowtcpforwarding yes\n'
  realatomic=mod.atomic; fired=[False]
  def atomic(path,data,mode,prior=None,uid=None):
   realatomic(path,data,mode,prior,uid)
   if keyfail and path==mod.AK and not fired[0]: fired[0]=True; raise RuntimeError('post key write fault')
  with patch.object(mod,'glob',type('G',(),{'glob':lambda *_:[]})), patch.object(mod.subprocess,'run',run), patch.object(mod.subprocess,'check_output',out), patch.object(mod,'atomic',atomic), patch.object(mod.sys,'stdin',io.StringIO(json.dumps(req))):
   if fail:
    with self.assertRaises(mod.subprocess.CalledProcessError): mod.main()
   else: mod.main()
  after=self.contents(); return before,after,calls,reloads[0]
 def test_plan_no_write(self):
  before,after,_,_=self.call('plan'); self.assertEqual(before,after)
 def test_apply_idempotent(self):
  _,a,_,_=self.call('apply'); _,b,_,_=self.call('apply'); self.assertEqual(a,b); self.assertEqual(a[0].count(b'10.10.20.10'),1); self.assertIn(b'from="192.168.4.6",restrict',a[0])
 def test_candidate_failure_no_write(self):
  before,after,_,_=self.call('apply',True); self.assertEqual(before,after)
 def test_canonical_mismatch_restores_before_key_grant(self):
  before=self.contents()
  with self.assertRaises(RuntimeError): self.call('apply',mismatch=True)
  after=self.contents(); self.assertEqual(before,after); self.assertNotIn(b'10.10.20.10',after[0])
 def test_early_match_and_unknown_include_refuse_without_writes(self):
  for extra in ('Match User root\n','Include /tmp/unknown.conf\n'):
   with open(mod.PATHS['main'],'a') as f: f.write(extra)
   before=self.contents()
   with self.assertRaises(RuntimeError): self.call('plan')
   self.assertEqual(before,self.contents())
   with open(mod.PATHS['main'],'wb') as f: f.write(before[1])
 def test_conflicting_drop_refuses_plan_without_writes(self):
  with open(mod.PATHS['drop'],'w') as f: f.write('foreign\n')
  os.chmod(mod.PATHS['drop'],0o600); before=self.contents()
  with self.assertRaises(RuntimeError): self.call('plan')
  self.assertEqual(before,self.contents())
 def test_reload_failure_restores_before_key_grant(self):
  before=self.contents()
  with self.assertRaises(mod.subprocess.CalledProcessError): self.call('apply',reloadfail=True)
  self.assertEqual(before,self.contents()); self.assertNotIn(b'10.10.20.10',self.contents()[0])
 def test_post_key_write_failure_restores_all_bytes(self):
  before=self.contents()
  with self.assertRaises(RuntimeError): self.call('apply',keyfail=True)
  self.assertEqual(before,self.contents())
 def test_existing_lab_key_missing_policy_recovers_without_duplicate(self):
  _,after,_,_=self.call('apply')
  os.unlink(mod.PATHS['drop'])
  _,recovered,_,_=self.call('apply')
  self.assertEqual(recovered[0].count(b'10.10.20.10'),1); self.assertIsNotNone(recovered[2])
 def test_ed25519_wire_validation(self):
  self.assertTrue(mod.valid_ed25519(self.key.split()[1]))
  for bad in ('AAAA','c3NoLXJzYQAAAAA=',self.key.split()[1]+'AA'):
   self.assertFalse(mod.valid_ed25519(bad))
 def test_extra_permitopen_and_unusable_lab_refuse(self):
  with self.assertRaises(RuntimeError): self.call('apply',extra=True)
  before=self.contents(); req={'action':'plan','lab_address':'10.10.20.1','lab_mac':'6c:1f:f7:d2:5d:97','public_key':self.key}
  with patch.object(mod.sys,'stdin',io.StringIO(json.dumps(req))):
   with self.assertRaises(RuntimeError): mod.main()
  self.assertEqual(before,self.contents())
 def test_lock_release_and_timeout(self):
  with mod.mutation_lock(): pass
  with mod.mutation_lock(): pass
  fd=os.open(mod.LOCKPATH,os.O_RDWR); fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  try:
   with patch.object(mod.time,'monotonic',side_effect=[0,6]):
    with self.assertRaisesRegex(RuntimeError,'timed out'):
     with mod.mutation_lock(): pass
  finally: fcntl.flock(fd,fcntl.LOCK_UN); os.close(fd)
 def test_concurrent_swap_is_preserved(self):
  old=mod.snapshot(mod.PATHS['main']); post=mod.atomic(mod.PATHS['main'],old[5]+b'owned\n',0o644,old)
  with open(mod.PATHS['main'],'wb') as f: f.write(b'concurrent\n')
  self.assertFalse(mod.restore_if_unchanged(mod.PATHS['main'],old,post,0o644))
  with open(mod.PATHS['main'],'rb') as f: self.assertEqual(f.read(),b'concurrent\n')
 def test_unrelated_supplemental_content_is_refused(self):
  home=os.path.join(self.d.name,'home')
  with open(home,'w') as f: f.write('from="192.168.4.6",restrict '+self.key+' home\n')
  with open(mod.PATHS['authorized_keys'],'w') as f: f.write('unrelated ssh-ed25519 '+('A'*43)+'=\n')
  os.chmod(home,0o600); os.chown(home,os.getuid(),os.getgid()); os.chmod(mod.PATHS['authorized_keys'],0o600)
  mod.PATHS['home_authorized_keys']=home
  mod.expected_mode=lambda path: 0o600 if path in (mod.PATHS['authorized_keys'],mod.PATHS['drop'],home) else 0o644
  with self.assertRaisesRegex(RuntimeError,'supplemental authorized_keys'): self.call('plan')
 def test_proxmox_symlink_apply_preserves_cluster_target(self):
  target=os.path.join(self.d.name,'cluster-authorized_keys'); link=os.path.join(self.d.name,'home-authorized_keys')
  with open(target,'w') as f: f.write('from="192.168.4.6",restrict '+self.key+' home\n')
  os.chmod(target,0o600); os.chown(target,os.getuid(),os.getgid()); os.symlink(target,link)
  mod.HOME_TARGET=os.path.realpath(target); mod.HOME_TARGET_GID=os.getgid(); mod.PATHS['home_authorized_keys']=link
  mod.expected_mode=lambda path: 0o600 if path in (mod.PATHS['authorized_keys'],mod.PATHS['drop'],target) else 0o644
  with open(mod.PATHS['authorized_keys'],'w') as f: f.write('')
  os.chmod(mod.PATHS['authorized_keys'],0o600)
  linkstat=os.lstat(link); targetstat=os.stat(target); targetbytes=open(target,'rb').read()
  self.call('apply'); self.call('apply')
  self.assertEqual(os.lstat(link).st_ino,linkstat.st_ino); self.assertEqual(os.stat(target).st_ino,targetstat.st_ino)
  self.assertEqual(open(target,'rb').read(),targetbytes)
  self.assertEqual(open(mod.PATHS['authorized_keys']).read().count(self.key),1)
 def test_unknown_home_symlink_refuses_without_writes(self):
  target=os.path.join(self.d.name,'other'); link=os.path.join(self.d.name,'home-authorized_keys')
  with open(target,'w') as f: f.write('unchanged\n')
  os.chmod(target,0o600); os.chown(target,os.getuid(),os.getgid()); os.symlink(target,link)
  mod.HOME_TARGET=os.path.join(self.d.name,'expected'); mod.PATHS['home_authorized_keys']=link
  before=open(target,'rb').read()
  with self.assertRaisesRegex(RuntimeError,'HOME authorized_keys link'): self.call('plan')
  self.assertEqual(open(target,'rb').read(),before)
 def test_invalid_effective_authorized_keys_baselines_refuse(self):
  before=self.contents()
  for baseline in ('none', mod.AK):
   with self.assertRaisesRegex(RuntimeError,'AuthorizedKeysFile baseline'): self.call('apply',baseline=baseline)
   self.assertEqual(before,self.contents())

if __name__=='__main__': unittest.main()
