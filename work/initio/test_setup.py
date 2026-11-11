"""Exercise installer Verify mode in throwaway folders, without installation."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
PS=r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'


class SetupVerificationTests(unittest.TestCase):
    def verify(self, *, content='test', path='payload.txt', product='initio-dvd-bridge/0.1.0-alpha.2'):
        with tempfile.TemporaryDirectory(prefix='installer-offline-',dir=ROOT/'work/initio') as temp:
            stage=Path(temp)
            shutil.copyfile(ROOT/'Setup.ps1',stage/'Setup.ps1')
            (stage/'payload.txt').write_text(content)
            (stage/'install-manifest.json').write_text(json.dumps({'product':product,'files':[
                {'path':path,'sha256':hashlib.sha256(b'test').hexdigest()}]}))
            env={k:v for k,v in os.environ.items() if k.upper()!='PSMODULEPATH'}
            env['PSModulePath']=str(Path(PS).parent/'Modules')
            result=subprocess.run([PS,'-NoProfile','-ExecutionPolicy','Bypass','-File',str(stage/'Setup.ps1'),'-Action','Verify'],
                                  capture_output=True,text=True,timeout=15,env=env)
            self.assertEqual(sorted(p.name for p in stage.iterdir()),['Setup.ps1','install-manifest.json','payload.txt'])
            return result

    def test_valid_manifest_verifies_without_writing_anything(self):
        result=self.verify()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('no installation or device access',result.stdout)

    def test_modified_payload_is_rejected(self):
        self.assertNotEqual(self.verify(content='changed').returncode,0)

    def test_parent_traversal_is_rejected(self):
        result=self.verify(path='../outside.txt')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('escapes',result.stderr)

    def test_foreign_manifest_is_rejected(self):
        self.assertNotEqual(self.verify(product='foreign').returncode,0)
