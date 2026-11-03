import ipaddress,struct,unittest
from audit_android_dns_fixture import response

def query(name,kind=1):
    labels=b''.join(bytes([len(v)])+v.encode() for v in name.split('.'))+b'\0'
    return struct.pack('!HHHHHH',123,0x100,1,0,0,0)+labels+struct.pack('!HH',kind,1)

class DnsFixtureTests(unittest.TestCase):
    def test_full_A_AAAA_answers_and_TTL_zero(self):
        for kind,address in ((1,'198.19.0.1'),(28,'2001:db8:29::1')):
            reply,row=response(query('q29-123.test',kind));self.assertTrue(row['answered']);self.assertEqual(reply[:2],b'\0{')
            self.assertEqual(struct.unpack('!HHHHHH',reply[:12]),(123,0x8180,1,1,0,0));at=len(query('q29-123.test',kind))
            self.assertEqual(struct.unpack('!HHIH',reply[at+2:at+12]),(kind,1,0,4 if kind==1 else 16));self.assertEqual(str(ipaddress.ip_address(reply[at+12:])),address)
    def test_provider_and_mismatch_bootstrap_A_only(self):
        for name in ('q29-dot.test','q29-dot-untrusted.test','q29-dot-mismatch.test'):
            reply,row=response(query(name));self.assertEqual(str(ipaddress.ip_address(reply[-4:])),'198.19.0.53');self.assertTrue(row['answered'])
            reply,row=response(query(name,28));self.assertFalse(row['answered']);self.assertEqual(struct.unpack('!H',reply[2:4])[0],0x8180)
    def test_unrelated_name_is_NXDOMAIN_not_fake_positive(self):
        reply,row=response(query('other.invalid'));self.assertFalse(row['answered']);self.assertEqual(struct.unpack('!H',reply[2:4])[0],0x8183)
    def test_truncated_question_rejected(self):
        for data in (b'',query('q29-123.test')[:-1],query('q29-123.test')[:15]):
            with self.assertRaises(AssertionError):response(data)
    def test_compressed_or_multiple_questions_rejected(self):
        with self.assertRaises(AssertionError):response(query('q29-123.test')[:12]+b'\xc0\x0c'+b'\0'*4)
        data=bytearray(query('q29-123.test'));data[5]=2
        with self.assertRaises(AssertionError):response(bytes(data))

if __name__=='__main__':unittest.main()
