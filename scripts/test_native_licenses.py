from __future__ import annotations
import hashlib, io, json, tarfile, tempfile, unittest
from pathlib import Path
from native_licenses import generate, check_bundle, export_bundle_zip, HEADERS


def fixture(root: Path, *, supplement=False, license_name='LICENSE'):
    repo=root/'repo'; (repo/'qeli').mkdir(parents=True); (repo/'LICENSE').write_bytes(b'core\n')
    archives=root/'archives';archives.mkdir(); receipts=root/'supplements';receipts.mkdir()
    content={'Cargo.toml': b'[package]\nname="demo"\nversion="1.0.0"\nlicense="MIT OR Apache-2.0"\nrepository="https://github.com/example/demo"\n'}
    records=[]
    if supplement:
        commit='1'*40
        content['.cargo_vcs_info.json']=json.dumps({'git':{'sha1':commit}}).encode()
        payload=b'upstream license\r\n';(receipts/'notice.txt').write_bytes(payload)
        records=[{'name':'demo','version':'1.0.0','vcs_commit':commit,'upstream_path':'LICENSE-MIT',
                  'url':'https://raw.githubusercontent.com/example/demo/'+commit+'/LICENSE-MIT',
                  'sha256':hashlib.sha256(payload).hexdigest(),'payload':'notice.txt'}]
    else:
        content[license_name]=b'upstream license\r\n'
    archive=archives/'demo-1.0.0.crate'
    with tarfile.open(archive,'w:gz') as t:
        for name,data in content.items():
            info=tarfile.TarInfo('demo-1.0.0/'+name);info.size=len(data);t.addfile(info,io.BytesIO(data))
    checksum=hashlib.sha256(archive.read_bytes()).hexdigest()
    (repo/'qeli/Cargo.lock').write_text('version = 4\n[[package]]\nname="qeli"\nversion="0.8.2"\n[[package]]\nname="demo"\nversion="1.0.0"\nsource="registry+https://github.com/rust-lang/crates.io-index"\nchecksum="'+checksum+'"\n',encoding='utf-8')
    (receipts/'receipts.json').write_text(json.dumps({'schema':1,'rows':records}),encoding='utf-8')
    output=repo/'qeli/third-party-notices/rust'
    return repo,archives,receipts,output


class NativeLicenseTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.repo,self.archives,self.receipts,self.bundle=fixture(Path(self.temp.name))
    def generate(self): return generate(self.repo,self.archives,self.receipts,self.bundle)
    def resource(self): return next((self.bundle/'files').rglob('*.txt'))
    def reindex(self):
        file=self.bundle/'INDEX.tsv';rows=file.read_text(encoding='utf-8').splitlines();new=[rows[0]]
        for row in rows[1:]:
            digest,name,origin=row.split('\t');new.append(hashlib.sha256((self.bundle/name).read_bytes()).hexdigest()+'\t'+name+'\t'+origin)
        file.write_text('\n'.join(new)+'\n',encoding='utf-8')
    def test_preserves_bytes_and_expressions(self):
        self.assertEqual(self.generate()['locked_packages'],1)
        self.assertEqual(self.resource().read_bytes(),b'upstream license\r\n')
        self.assertIn('MIT OR Apache-2.0',(self.bundle/'PACKAGES.tsv').read_text(encoding='utf-8'))
    def test_router_zip_deterministic_and_exact(self):
        import zipfile
        self.generate();destination=self.repo/'release/legal.zip'
        first=export_bundle_zip(self.repo,destination)
        second=export_bundle_zip(self.repo,destination)
        self.assertEqual(first['zip_sha256'],second['zip_sha256'])
        with zipfile.ZipFile(destination) as archive:
            self.assertEqual(len(archive.namelist()),len(list(path for path in self.bundle.rglob('*') if path.is_file())))
            for file in self.bundle.rglob('*'):
                if file.is_file():self.assertEqual(archive.read('rust/'+file.relative_to(self.bundle).as_posix()),file.read_bytes())
    def test_router_export_rejects_corrupt_bundle(self):
        self.generate();self.resource().write_bytes(b'corrupt')
        with self.assertRaisesRegex(ValueError,'checksum'):export_bundle_zip(self.repo,self.repo/'release/legal.zip')

    def test_archive_checksum_rejected(self):
        with (self.archives/'demo-1.0.0.crate').open('ab') as f:f.write(b'tamper')
        with self.assertRaisesRegex(ValueError,'checksum'):self.generate()
    def test_lock_binding_drift(self):
        self.generate();file=self.repo/'qeli/Cargo.lock';file.write_bytes(file.read_bytes()+b'# changed\n')
        with self.assertRaisesRegex(ValueError,'binding'):check_bundle(self.repo)
    def test_missing_resource(self):
        self.generate();self.resource().unlink()
        with self.assertRaisesRegex(ValueError,'missing/checksum'):check_bundle(self.repo)
    def test_modified_resource(self):
        self.generate();self.resource().write_bytes(b'tamper')
        with self.assertRaisesRegex(ValueError,'checksum'):check_bundle(self.repo)
    def test_unknown_file(self):
        self.generate();(self.bundle/'unexpected.txt').write_bytes(b'extra')
        with self.assertRaisesRegex(ValueError,'unindexed'):check_bundle(self.repo)
    def test_duplicate_index(self):
        self.generate();f=self.bundle/'INDEX.tsv';data=f.read_text(encoding='utf-8');f.write_text(data+data.splitlines()[1]+'\n',encoding='utf-8')
        with self.assertRaisesRegex(ValueError,'Duplicate'):check_bundle(self.repo)
    def test_index_traversal(self):
        self.generate();f=self.bundle/'INDEX.tsv';f.write_text(HEADERS['INDEX.tsv']+'\n'+'0'*64+'\t../escape\torigin\n',encoding='utf-8')
        with self.assertRaisesRegex(ValueError,'Unsafe'):check_bundle(self.repo)
    def test_inventory_checksum_binding(self):
        self.generate();f=self.bundle/'PACKAGES.tsv';data=f.read_text(encoding='utf-8').splitlines();values=data[1].split('\t');values[3]='0'*64
        f.write_text(data[0]+'\n'+'\t'.join(values)+'\n',encoding='utf-8');self.reindex()
        with self.assertRaisesRegex(ValueError,'inventory drift'):check_bundle(self.repo)
    def test_project_license_drift(self):
        self.generate();(self.repo/'LICENSE').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'Qeli license'):check_bundle(self.repo)
    def test_unknown_registry(self):
        f=self.repo/'qeli/Cargo.lock';f.write_bytes(f.read_bytes().replace(b'github.com/rust-lang/crates.io-index',b'example.com/registry'))
        with self.assertRaisesRegex(ValueError,'Unreviewed Cargo source'):self.generate()
    def test_refuses_existing_output(self):
        self.generate()
        with self.assertRaisesRegex(ValueError,'new directory'):self.generate()
    def test_exact_vcs_supplement(self):
        with tempfile.TemporaryDirectory() as root:
            repo,a,r,o=fixture(Path(root),supplement=True)
            self.assertEqual(generate(repo,a,r,o)['supplements'],1)
    def test_wrong_vcs_supplement(self):
        with tempfile.TemporaryDirectory() as root:
            repo,a,r,o=fixture(Path(root),supplement=True);f=r/'receipts.json';data=json.loads(f.read_text(encoding='utf-8'));data['rows'][0]['vcs_commit']='2'*40;f.write_text(json.dumps(data),encoding='utf-8')
            with self.assertRaisesRegex(ValueError,'VCS'):generate(repo,a,r,o)
    def test_authors_license_preserved(self):
        with tempfile.TemporaryDirectory() as root:
            repo,a,r,o=fixture(Path(root),license_name='AUTHORS');self.assertEqual(generate(repo,a,r,o)['resources'],1)

if __name__=='__main__':unittest.main()
