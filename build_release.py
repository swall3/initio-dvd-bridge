"""Build a pinned Windows bundle; never install, start, or probe hardware."""
import hashlib
import json
import re
import os
from pathlib import Path
import subprocess
import sys
import urllib.request
import zipfile

ROOT=Path(__file__).resolve().parent
VERSION='0.1.0-alpha.2'
URL='https://www.python.org/ftp/python/3.13.17/python-3.13.17-embed-amd64.zip'
SHA256='9e35319bffedab8b36ad44d8f377cb4f1733bcec257a0b6d04d94f01486ddb38'
PS=r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'


def source_files():
    files=[p for p in ROOT.iterdir() if p.is_file() and p.suffix in ('.py','.ps1','.cmd','.md','.cs')]
    files += [ROOT/'LICENSE', ROOT/'outputs/initio-sata/InitioSata.py']
    files += sorted((ROOT/'work/initio').glob('*.py'))
    files += sorted((ROOT/'work/initio').glob('*.ps1'))
    files += sorted((ROOT/'docs').glob('*.md'))
    return sorted(set(files))


def main():
    if sys.platform!='win32':raise RuntimeError('Build and test on Windows x64')
    environment={k:v for k,v in os.environ.items() if k.upper()!='PSMODULEPATH'}
    environment['PSModulePath']=str(Path(PS).parent/'Modules')
    dist=ROOT/'dist';dist.mkdir(exist_ok=True)
    download=dist/'python-embed.zip'
    if not download.exists():
        with urllib.request.urlopen(URL,timeout=60) as response:
            download.write_bytes(response.read())
    if hashlib.sha256(download.read_bytes()).hexdigest()!=SHA256:
        raise RuntimeError('Python archive checksum mismatch')
    runtime=ROOT/'runtime';runtime.mkdir(exist_ok=True)
    with zipfile.ZipFile(download) as z:
        for name in z.namelist():
            if not (runtime/name).resolve().is_relative_to(runtime.resolve()):
                raise RuntimeError('Archive path outside runtime')
        z.extractall(runtime)
    (runtime/'python313._pth').write_text('python313.zip\n.\n../work/initio\n../outputs/initio-sata\n')
    check="""$s=Get-AuthenticodeSignature -LiteralPath $args[0]; if($s.Status -ne 'Valid' -or $s.SignerCertificate.Subject -notmatch 'O=Python Software Foundation'){throw 'Python signature failed'}"""
    signature=dist/'verify-python.ps1';signature.write_text(check)
    subprocess.run([PS,'-NoProfile','-ExecutionPolicy','Bypass','-File',str(signature),str(runtime/'python.exe')],check=True,env=environment)
    test=subprocess.run([str(runtime/'python.exe'),str(ROOT/'work/initio/run_dvd_offline_tests.py')],cwd=ROOT,capture_output=True,text=True)
    (dist/'offline-tests.txt').write_text(test.stdout+test.stderr)
    if test.returncode:raise RuntimeError(test.stdout+test.stderr)
    compiler=Path(os.environ['SystemRoot'])/'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
    assemblies=list((Path(os.environ['SystemRoot'])/'Microsoft.NET/assembly/GAC_MSIL/System.Management.Automation').glob('*/System.Management.Automation.dll'))
    if len(assemblies)!=1:raise RuntimeError('Cannot uniquely locate Windows PowerShell hosting assembly')
    gui=ROOT/'DVD Controls.exe'
    subprocess.run([str(compiler),'/nologo','/target:winexe','/platform:x64','/out:'+str(gui),
                    '/reference:System.Windows.Forms.dll','/reference:'+str(assemblies[0]),str(ROOT/'TrayHost.cs')],check=True)
    files=source_files()+[gui]+sorted(p for p in runtime.iterdir() if p.is_file())
    for path in source_files():
        text=path.read_text(encoding='utf-8')
        if path.suffix=='.py':compile(text,path.name,'exec')
        if re.search(r'(?i)[a-z]:\\users\\[^\\\s]+', text):
            raise RuntimeError('Private development identifier in '+str(path.relative_to(ROOT)))
    manifest={'product':'initio-dvd-bridge/'+VERSION,'files':[
        {'path':p.relative_to(ROOT).as_posix(),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in files]}
    mpath=ROOT/'install-manifest.json';mpath.write_text(json.dumps(manifest,indent=2))
    subprocess.run([PS,'-NoProfile','-ExecutionPolicy','Bypass','-File',str(ROOT/'Setup.ps1'),'-Action','Verify'],check=True,env=environment)
    archive=dist/f'Initio-DVD-Bridge-{VERSION}-win64.zip'
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
        for p in [*files,mpath]:z.write(p,p.relative_to(ROOT).as_posix())
    with zipfile.ZipFile(archive) as z:
        if z.testzip():raise RuntimeError('ZIP integrity failure')
    digest=hashlib.sha256(archive.read_bytes()).hexdigest()
    (dist/'SHA256SUMS.txt').write_text(digest+'  '+archive.name+'\n')
    print(test.stdout+test.stderr)
    print(archive.name,archive.stat().st_size,digest)


if __name__=='__main__':main()
