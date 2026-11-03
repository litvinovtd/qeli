"""Regression: accepted TCP streams can arrive in a different order across carriers."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from benchmark_evidence import parse_iperf_bidir, validate_iperf_tcp_bidir_roles
from benchmark_report import aggregate
from test_benchmark_bidir import bidir_fixture, raw_result
from test_benchmark_report import write


def role_result(parallel=1, address='10.9.0.2', peer='10.9.0.1'):
    result = raw_result()
    result['start']['test_start']['num_streams'] = parallel
    result['start']['connected'] = []
    result['end']['streams'] = []
    server = dict(start=dict(connected=[]), end=dict(streams=[]))
    for index in range(2 * parallel):
        sock, port, sender = index + 5, 33208 + index, index < parallel
        conn = dict(socket=sock, local_host=address, local_port=port, remote_host=peer, remote_port=5203)
        result['start']['connected'].append(conn)
        result['end']['streams'].append(dict(sender=dict(socket=sock, sender=sender)))
        server['start']['connected'].insert(0, dict(socket=sock + 20, local_host=peer, local_port=5203, remote_host=address, remote_port=port))
        server['end']['streams'].insert(0, dict(sender=dict(socket=sock + 20, sender=not sender)))
    result['server_output_json'] = server
    return result


def text_output(raw):
    server = raw.pop('server_output_json')
    roles = {x['sender']['socket']:x['sender']['sender'] for x in server['end']['streams']}
    raw['server_output_text'] = ''.join(
        f"[ {c['socket']}] local {c['local_host']} port {c['local_port']} connected to {c['remote_host']} port {c['remote_port']}\n"
        f"[ {c['socket']}][{'TX-S' if roles[c['socket']] else 'RX-S'}] 0.00-8.00 sec measurement\n"
        for c in server['start']['connected'])
    return raw


class StreamRoleTests(unittest.TestCase):
    def test_matches_endpoints_even_with_reversed_array_order_p1_p4_ipv4_ipv6(self):
        for parallel in (1,4):
            for addresses in (('10.9.0.2','10.9.0.1'),('fd42:36:9::2','fd42:36:9::1')):
                for text in (False,True):
                    raw=role_result(parallel,*addresses)
                    if text:text_output(raw)
                    with self.subTest(parallel=parallel,addresses=addresses,text=text):
                        proof=validate_iperf_tcp_bidir_roles(raw,parallel)
                        self.assertEqual(len(proof),2*parallel)
                        self.assertTrue(all(x['client_sender']!=x['server_sender'] for x in proof))
                        self.assertEqual(parse_iperf_bidir(raw,8,parallel,require_tcp_roles=True)['down_mbps'],200)

    def test_real_archived_zero_progress_is_classified_as_role_conflict_first(self):
        raw=json.loads((Path(__file__).parent/'fixtures/benchmark_tcp_bidir_role_conflict.json').read_text())
        for required in (False,True):
            with self.assertRaisesRegex(ValueError,'endpoint roles conflict'):
                parse_iperf_bidir(raw,8,1,require_tcp_roles=required)

    def test_missing_peer_evidence_and_partial_maps_cannot_be_admitted(self):
        raw=role_result();del raw['server_output_json']
        with self.assertRaisesRegex(ValueError,'server role evidence missing'):
            parse_iperf_bidir(raw,8,1,require_tcp_roles=True)
        for source,key in (('start','connected'),('end','streams')):
            raw=role_result();raw['server_output_json'][source][key].pop()
            with self.assertRaisesRegex(ValueError,'streams missing'):
                validate_iperf_tcp_bidir_roles(raw,1)
        raw=text_output(role_result());raw['server_output_text']=raw['server_output_text'].replace('[RX-S]','[UNKNOWN]')
        with self.assertRaisesRegex(ValueError,'role missing'):
            validate_iperf_tcp_bidir_roles(raw,1)

    def test_crossed_roles_are_rejected_even_with_positive_receiver_summaries(self):
        for text in (False,True):
            raw=role_result()
            for stream in raw['server_output_json']['end']['streams']:
                stream['sender']['sender']=not stream['sender']['sender']
            if text:text_output(raw)
            with self.assertRaisesRegex(ValueError,'endpoint roles conflict'):
                parse_iperf_bidir(raw,8,1)

    def test_duplicate_endpoint_socket_and_invalid_flags_are_rejected(self):
        for target in ('client','server'):
            for field in ('socket','local_port'):
                raw=role_result();data=raw if target=='client' else raw['server_output_json']
                data['start']['connected'][1][field]=data['start']['connected'][0][field]
                # Server peers differ only in remote_port, not local_port.
                if target=='server' and field=='local_port':data['start']['connected'][1]['remote_port']=data['start']['connected'][0]['remote_port']
                with self.subTest(target=target,field=field),self.assertRaises(ValueError):
                    validate_iperf_tcp_bidir_roles(raw,1)
        raw=role_result();raw['end']['streams'][0]['sender']['sender']=1
        with self.assertRaisesRegex(ValueError,'role missing'):
            validate_iperf_tcp_bidir_roles(raw,1)
        for flag in (None,1,'true'):
            with self.assertRaises(ValueError):parse_iperf_bidir(role_result(),8,1,require_tcp_roles=flag)

    def test_ipv4_mapped_ipv6_matches_literal_ipv4(self):
        raw=role_result()
        for conn in raw['server_output_json']['start']['connected']:
            for side in ('local','remote'):conn[side+'_host']='::ffff:'+conn[side+'_host']
        self.assertEqual(len(validate_iperf_tcp_bidir_roles(raw,1)),2)

    def test_offline_report_enforces_declared_policy_but_preserves_old_format(self):
        with tempfile.TemporaryDirectory() as temporary:
            roots=[bidir_fixture(Path(temporary)/str(i),i) for i in range(3)]
            self.assertEqual(aggregate(roots)['status'],'AGGREGATED')
            for root in roots:
                path=root/'results.json';v=json.loads(path.read_text());v['meta']['tcp_bidir_stream_roles_required']=True;write(path,v)
            with self.assertRaises(ValueError):aggregate(roots)


if __name__=='__main__':unittest.main()
