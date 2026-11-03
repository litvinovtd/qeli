"""Reports must retain comparable independent runs and revalidate raw data."""

import copy
import datetime as dt
import json
import math
from pathlib import Path
import sys
import tempfile
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from benchmark_evidence import parse_iperf_result
from benchmark_report import aggregate, population
from benchmark_host_state import COMMANDS, SCHEMA


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding='utf-8')


def fixture(root, index, rate):
    started = dt.datetime(2026, 10, 10, tzinfo=dt.timezone.utc) + dt.timedelta(minutes=index * 10)
    host = dict(kernel='Linux fixture', cpu='2 CPU fixture', iperf='iperf 3.18', version='qeli fixture',
                boot_id='boot fixture', cpu_governor=dict(availability='UNAVAILABLE', policies={}))
    meta = dict(date=started.isoformat(), finished_at=(started + dt.timedelta(seconds=100)).isoformat(),
        elapsed_seconds=100, run_id=str(uuid.uuid5(uuid.NAMESPACE_URL, str(index))),
        binary_sha256='a' * 64, harness_sha256='b' * 64, configuration_builder_sha256='c' * 64,
        admission_sha256='d' * 64, local_native_source_digest='e' * 64,
        binary_source_provenance='UNVERIFIED', seconds=8, tcp_parallel=1, recordizer='off',
        topology='two VM fixture', hosts=['10.66.116.10', '10.66.116.11'],
        selected_modes=['tcp-fixture', 'udp-fixture'], server=copy.deepcopy(host), client=copy.deepcopy(host))
    core = dict(addresses='IPv4 fixture', routes='route fixture', qeli_listener='listener443 fixture')
    run = dict(schema_version=2, status='COMPLETED', errors=[], host_restored=True,
               host_before=[dict(core), dict(core)], host_after=[dict(core), dict(core)], meta=meta, baseline={}, modes={})
    for name, transport in (('direct', 'tcp'), ('tcp-fixture', 'tcp'), ('udp-fixture', 'udp')):
        row = run['baseline'] if name == 'direct' else dict(status='COMPLETED', transport=transport,
            configuration_template_sha256='f' * 64, pids=dict(server=123, client=456),
            mtus=dict(server=dict(qbench0=1400, qd14v=1500), client=dict(qbench0=1400, qd14v=1500)),
            **{'qeli-bench-s_rmem_max': 4194304, 'qeli-bench-c_rmem_max': 4194304})
        phases = ['tcp_up', 'tcp_down'] + (['udp_500'] if name == 'direct' else ['udp_100', 'udp_500'] if transport == 'udp' else [])
        for phase in phases:
            udp = phase.startswith('udp_')
            seconds = 5 if udp else 8
            received = dict(seconds=seconds, bytes=int(rate * 1e6 * seconds / 8), bits_per_second=rate * 1e6)
            if udp:
                received.update(lost_percent=1, jitter_ms=.2)
            raw = dict(start=dict(timestamp=dict(timesecs=index)), end=dict(sum_received=received, sum_sent=dict(retransmits=3)))
            write(root / name / (phase + '-iperf.json'), raw)
            metrics = parse_iperf_result(raw, 'udp' if udp else 'tcp', seconds)
            row[phase] = {key: metrics[key] for key in ('mbps', 'lost_percent', 'retransmits')} if name == 'direct' else metrics
            if name == 'direct':
                continue
            samples = []
            for pid in (123, 456):
                first = dict(t=100, ticks=10, start=str(index + 100), cpu_affinity='0-1', nice=0,
                             rss_kib=100, host_total=100, host_steal=1, host_load=[.1, .2, .3])
                last = dict(first, t=100 + seconds + 1, ticks=10 + (seconds + 1) * 20,
                            rss_kib=120, host_total=100 + (seconds + 1) * 100,
                            host_steal=1 + seconds + 1)
                samples.append(dict(pid=pid, clock_ticks=100, cpu_avg_pct=20, rss_peak_kib=120,
                                    elapsed=seconds + 1, host_steal_pct=1, samples=[first, last]))
            write(root / name / (phase + '-processes.json'), samples)
            row[phase].update(server=samples[0], client=samples[1], kernel_rcvbuf_drops=0, server_session_drops=0)
            before = dict(kernel=dict(RcvbufErrors=0), application=dict(dropped=0, bytes_sent=0,
                          bytes_recv=0, connected_secs=0, ip='10.9.0.2', peer='10.255.42.2:1234'))
            after = copy.deepcopy(before)
            after['application'].update(bytes_sent=1000, bytes_recv=1000, connected_secs=seconds + 1)
            write(root / name / (phase + '-counters.json'), dict(before=before, after=after))
        if name != 'direct':
            run['modes'][name] = row
    write(root / 'results.json', run)
    return root


class BenchmarkReportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.runs = [fixture(self.root / str(index), index, rate) for index, rate in enumerate((200, 100, 300))]

    def tearDown(self):
        self.temporary.cleanup()

    def mutate(self, relative, update, run=1):
        path = self.runs[run] / relative
        value = json.loads(path.read_text())
        update(value)
        write(path, value)

    def test_all_runs_and_raw_hashes_are_retained(self):
        report = aggregate(self.runs)
        stats = report['statistics']['udp-fixture/udp_500']['mbps']
        self.assertEqual((stats['n'], stats['min'], stats['median'], stats['max']), (3, 100, 200, 300))
        self.assertEqual(report['status'], 'AGGREGATED')
        self.assertEqual(len(report['inputs']), 3)
        self.assertEqual(len(report['inputs'][0]['hashes']), 22)
        self.assertIn('UNVERIFIED', report['scope'])

    def test_two_runs_cannot_become_a_statistical_report(self):
        with self.assertRaisesRegex(ValueError, 'at least three'):
            aggregate(self.runs[:2])

    def test_empty_archived_snapshots_cannot_claim_restoration(self):
        self.mutate('results.json', lambda run: run.update(host_before=[{}, {}], host_after=[{}, {}]))
        with self.assertRaisesRegex(ValueError, 'core snapshot incomplete'):
            aggregate(self.runs)

    def test_full_backend_counters_are_recomputed_and_missing_backend_refuses(self):
        before = {key: 'fixture' for key in COMMANDS}
        before.update(snapshot_schema=SCHEMA, nft='{"nftables":[]}', legacy4='*filter\n:INPUT ACCEPT [1:2]\nCOMMIT')
        after = dict(before, legacy4='*filter\n:INPUT ACCEPT [50:1000]\nCOMMIT')
        for index in range(3):
            self.mutate('results.json', lambda run: run.update(host_before=[before, before], host_after=[after, after]), run=index)
            self.mutate('results.json', lambda run: run['meta'].update(host_state_sha256='9' * 64), run=index)
        self.assertEqual(aggregate(self.runs)['comparison']['host_snapshot_coverage'], SCHEMA)
        self.mutate('results.json', lambda run: run['host_after'][0].pop('legacy6'))
        with self.assertRaisesRegex(ValueError, 'population incomplete'):
            aggregate(self.runs)

    def test_claimed_restoration_cannot_hide_nft_rule_change(self):
        before = {key: 'fixture' for key in COMMANDS}
        before.update(snapshot_schema=SCHEMA, nft='{"nftables":[{"rule":{"expr":[{"accept":null}]}}]}')
        after = dict(before, nft='{"nftables":[{"rule":{"expr":[{"drop":null}]}}]}')
        self.mutate('results.json', lambda run: run.update(host_before=[before, before], host_after=[after, after]))
        with self.assertRaisesRegex(ValueError, 'host state restoration'):
            aggregate(self.runs)

    def test_full_and_archived_core_coverage_cannot_be_mixed(self):
        state = {key: 'fixture' for key in COMMANDS}
        state.update(snapshot_schema=SCHEMA, nft='{"nftables":[]}')
        self.mutate('results.json', lambda run: run.update(host_before=[state, state], host_after=[state, state]))
        self.mutate('results.json', lambda run: run['meta'].update(host_state_sha256='9' * 64))
        with self.assertRaisesRegex(ValueError, 'runs differ'):
            aggregate(self.runs)

    def test_repeating_directory_or_run_identity_refuses(self):
        with self.assertRaisesRegex(ValueError, 'duplicate run'):
            aggregate([self.runs[0], self.runs[0], self.runs[2]])
        first = json.loads((self.runs[0] / 'results.json').read_text())
        self.mutate('results.json', lambda value: value['meta'].update(run_id=first['meta']['run_id']))
        with self.assertRaisesRegex(ValueError, 'duplicate run'):
            aggregate(self.runs)

    def test_one_copied_phase_cannot_inflate_an_independent_population(self):
        for mode, phase in [('tcp-fixture', 'tcp_up'), ('udp-fixture', 'udp_500')]:
            fixture(self.runs[1], 1, 100)
            relative = mode + '/' + phase + '-iperf.json'
            (self.runs[1] / relative).write_bytes((self.runs[0] / relative).read_bytes())
            first = json.loads((self.runs[0] / 'results.json').read_text())
            metrics = first['modes'][mode][phase]
            # Preserve the second run's independent process/counter samples so the
            # duplicated raw throughput phase is the only violated admission rule.
            self.mutate('results.json', lambda run: run['modes'][mode][phase].update(
                {key: metrics[key] for key in ('mbps', 'retransmits', 'lost_percent', 'jitter_ms')}))
            for measurements_only in (False, True):
                with self.subTest(mode=mode, measurements_only=measurements_only):
                    with self.assertRaisesRegex(ValueError, 'duplicated raw iperf phase'):
                        aggregate(self.runs, measurements_only=measurements_only)

    def test_equal_rates_from_distinct_raw_measurements_remain_valid(self):
        for index, root in enumerate(self.runs):
            fixture(root, index, 200)
        report = aggregate(self.runs)
        self.assertEqual(report['statistics']['tcp-fixture/tcp_up']['mbps']['n'], 3)
        self.assertEqual(report['statistics']['tcp-fixture/tcp_up']['mbps']['median'], 200)

    def test_failed_run_is_not_discarded(self):
        self.mutate('results.json', lambda value: value.update(status='FAIL'))
        with self.assertRaisesRegex(ValueError, 'run incomplete'):
            aggregate(self.runs)

    def test_missing_phase_or_raw_file_refuses(self):
        self.mutate('results.json', lambda value: value['modes']['tcp-fixture'].pop('tcp_down'))
        with self.assertRaisesRegex(ValueError, 'phase population'):
            aggregate(self.runs)
        fixture(self.runs[1], 1, 100)
        (self.runs[1] / 'tcp-fixture' / 'tcp_down-iperf.json').unlink()
        with self.assertRaises(FileNotFoundError):
            aggregate(self.runs)

    def test_changed_parallelism_or_mtu_refuses(self):
        self.mutate('results.json', lambda value: value['meta'].update(tcp_parallel=4))
        with self.assertRaisesRegex(ValueError, 'runs differ'):
            aggregate(self.runs)
        fixture(self.runs[1], 1, 100)
        self.mutate('results.json', lambda value: value['modes']['tcp-fixture']['mtus']['server'].update(qbench0=1280))
        with self.assertRaisesRegex(ValueError, 'runs differ'):
            aggregate(self.runs)

    def test_overlap_and_shortened_window_refuse(self):
        first = json.loads((self.runs[0] / 'results.json').read_text())
        self.mutate('results.json', lambda value: value['meta'].update(date=first['meta']['date']))
        with self.assertRaisesRegex(ValueError, 'overlapping runs'):
            aggregate(self.runs)
        fixture(self.runs[1], 1, 100)
        self.mutate('results.json', lambda value: value['meta'].update(elapsed_seconds=1))
        with self.assertRaisesRegex(ValueError, 'shorter than mandatory'):
            aggregate(self.runs)

    def test_raw_rate_cannot_disagree_with_summary(self):
        self.mutate('tcp-fixture/tcp_up-iperf.json', lambda value: value['end']['sum_received'].update(bits_per_second=1))
        with self.assertRaisesRegex(ValueError, 'summary disagrees with raw iperf'):
            aggregate(self.runs)

    def test_sampler_summary_is_recomputed(self):
        self.mutate('tcp-fixture/tcp_up-processes.json', lambda value: value[0].update(cpu_avg_pct=99))
        self.mutate('results.json', lambda value: value['modes']['tcp-fixture']['tcp_up']['server'].update(cpu_avg_pct=99))
        with self.assertRaisesRegex(ValueError, 'sampler summary disagrees'):
            aggregate(self.runs)

    def test_reset_session_counter_refuses(self):
        self.mutate('tcp-fixture/tcp_up-counters.json', lambda value: value['before']['application'].update(bytes_sent=2000))
        with self.assertRaisesRegex(ValueError, 'counters reset'):
            aggregate(self.runs)

    def test_copies_with_new_run_ids_cannot_be_independent_samples(self):
        for index, root in enumerate(self.runs):
            fixture(root, index, 100)
        for root in self.runs[1:]:
            for path in self.runs[0].rglob('*-iperf.json'):
                (root / path.relative_to(self.runs[0])).write_bytes(path.read_bytes())
        with self.assertRaisesRegex(ValueError, 'duplicated raw iperf'):
            aggregate(self.runs)

    def test_nonfinite_raw_json_refuses(self):
        self.mutate('udp-fixture/udp_500-iperf.json', lambda value: value['end']['sum_received'].update(jitter_ms=math.nan))
        with self.assertRaisesRegex(ValueError, 'nonfinite JSON'):
            aggregate(self.runs)

    def test_zero_and_extreme_rates_keep_finite_statistics(self):
        self.assertEqual(population([0, 0, 0])['median'], 0)
        self.assertEqual(population([1e308] * 4)['median'], 1e308)


if __name__ == '__main__':
    unittest.main()
