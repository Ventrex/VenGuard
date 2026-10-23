"""Actual local UDP/TCP protocol checks and incident/recovery regressions."""
import copy
import json
import socket
import struct
import tempfile
import threading
import time
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from connectivity import dns_probe,dns_check,tcp_probe,assessment,_name
from server import Store
from test_hub import FakeStore,SERVERS

GOOD={'ok':True,'reachable':True,'resolved':True,'ms':1,'error':'','code':'NOERROR'}
BAD={'ok':False,'reachable':False,'resolved':False,'ms':None,'error':'Geen antwoord binnen 2 seconden.','code':'timeout'}

class ProtocolTests(unittest.TestCase):
    def response(self,transport='udp',rcode=0,address='93.184.215.14',wrong_question=False,truncate=False):
        sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM if transport=='tcp' else socket.SOCK_DGRAM)
        sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        if transport=='tcp':sock.listen(1)
        def serve():
            try:
                if transport=='tcp':
                    connection,_=sock.accept();connection.settimeout(2)
                    length=struct.unpack('!H',connection.recv(2))[0];data=connection.recv(length)
                else:data,peer=sock.recvfrom(4096)
                answer=bool(address and not rcode and not truncate)
                flags=0x8180|rcode|(0x200 if truncate else 0)
                question=data[12:]
                if wrong_question:question=question.replace(b'example',b'invalid')
                payload=data[:2]+struct.pack('!HHHHH',flags,1,int(answer),0,0)+question
                if answer:payload+=b'\xc0\x0c'+struct.pack('!HHIH',1,1,60,4)+socket.inet_aton(address)
                if transport=='tcp':
                    wire=struct.pack('!H',len(payload))+payload
                    # A TCP DNS message can arrive in several reads.
                    for part in (wire[:1],wire[1:8],wire[8:]):connection.sendall(part)
                    connection.close()
                else:sock.sendto(payload,peer)
            finally:sock.close()
        thread=threading.Thread(target=serve,daemon=True);thread.start()
        result=dns_probe('127.0.0.1',port,timeout=1,transport=transport);thread.join(2)
        return result
    def test_udp_and_split_tcp_answer(self):
        for transport in ('udp','tcp'):
            result=self.response(transport)
            self.assertTrue(result['ok']);self.assertTrue(result['resolved']);self.assertEqual(result['answers'],['93.184.215.14'])
    def test_servfail_is_reachable_but_not_working(self):
        result=self.response(rcode=2);self.assertTrue(result['reachable']);self.assertFalse(result['ok']);self.assertEqual(result['code'],'SERVFAIL')
        self.assertEqual(assessment({'dns':result})['code'],'resolution')
    def test_nxdomain_is_response_not_proof_of_resolution(self):
        result=self.response(rcode=3);self.assertTrue(result['ok']);self.assertFalse(result['resolved'])
        self.assertEqual(assessment({'dns':result})['code'],'resolution')
    def test_block_address_and_empty_answer_not_successful_resolution(self):
        for address in ('0.0.0.0','127.0.0.1',None):self.assertFalse(self.response(address=address)['resolved'])
    def test_truncated_and_wrong_question_are_not_healthy(self):
        self.assertFalse(self.response(truncate=True)['ok'])
        self.assertFalse(self.response(wrong_question=True)['ok'])
        with self.assertRaises(ValueError):_name(b'\xc0\x00',0)
    def test_tcp_fallback_explains_udp_problem(self):
        with patch('connectivity.dns_probe',side_effect=[BAD,BAD,GOOD]):result=dns_check('192.0.2.10',53)
        self.assertFalse(result['ok']);self.assertTrue(result['tcp']['ok']);self.assertEqual(assessment({'dns':result})['code'],'udp')
    def test_tcp_refusal_has_specific_error(self):
        sock=socket.socket();sock.bind(('127.0.0.1',0));port=sock.getsockname()[1];sock.close()
        self.assertEqual(tcp_probe('127.0.0.1',port)['code'],'refused')
    def test_working_dns_is_not_called_down_for_failed_admin(self):
        self.assertEqual(assessment({'dns':GOOD,'api_ok':False,'checked_epoch':time.time()})['code'],'admin')

class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.s=FakeStore(self.tmp.name)
        self.s.config['servers']=copy.deepcopy(SERVERS);self.s.config['primary_id']='one';self.s.align_primary()
        self.s.offline=set();self.s.calls=[];self.s.user_rules={'one':[],'two':[]}
    def tearDown(self):self.tmp.cleanup()
    def check(self,result,external=True):
        with patch('connectivity.dns_check',return_value=copy.deepcopy(result)),patch('connectivity.tcp_probe',return_value={'ok':external,'ms':1,'error':'' if external else 'timeout'}):self.s.check_connectivity()
    def test_incident_coalesces_and_recovery_survives_restart(self):
        self.check(BAD);self.check(BAD)
        dns=[e for e in self.s.connectivity['incidents'] if e['key'].endswith(':dns')]
        self.assertEqual(len(dns),2);self.assertTrue(all(not e['ended_at'] for e in dns))
        self.check(GOOD);self.assertTrue(all(e['ended_at'] for e in dns))
        self.assertTrue(all(e['end_reason']=='recovered' for e in dns))
        loaded=Store(self.tmp.name);self.assertEqual(len(loaded.connectivity['incidents']),2)
        self.assertNotIn('one-secret',json.dumps(self.s.connectivity_snapshot(report=True)))
    def test_restart_does_not_claim_recovery_or_measured_downtime(self):
        self.check(BAD);loaded=Store(self.tmp.name)
        incident=loaded.connectivity['incidents'][0]
        self.assertEqual(incident['end_reason'],'monitor_restarted');self.assertIsNone(incident['duration_seconds'])
    def test_external_failure_not_merged_with_dns_outage(self):
        self.check(GOOD,external=False)
        self.assertEqual([e['key'] for e in self.s.connectivity['incidents']],['external'])
        self.assertTrue(self.s.health['one']['dns']['ok'])
        self.check(GOOD);self.assertEqual(self.s.connectivity['incidents'][0]['end_reason'],'recovered')
    def test_dns_update_not_blocked_by_admin_monitor(self):
        entered=threading.Event();release=threading.Event();original=self.s.agh
        def slow(path,*args,**kwargs):
            if path=='status':entered.set();release.wait(3)
            return original(path,*args,**kwargs)
        with patch.object(self.s,'agh',side_effect=slow):
            monitor=threading.Thread(target=self.s.monitor,kwargs={'include_dns':False});monitor.start();self.assertTrue(entered.wait(1))
            self.check(GOOD);self.assertTrue(self.s.health['one']['dns']['ok'])
            release.set();monitor.join(3)
            self.assertTrue(self.s.health['one']['dns']['resolved']);self.assertFalse(monitor.is_alive())
    def test_filtering_mismatch_visible_per_server(self):
        self.s.health={'one':{'api_ok':True,'checked_at':'2026-10-23T12:00:00+00:00','checked_epoch':time.time(),'dns':GOOD,'protection_enabled':False}}
        snapshot=self.s.hub_snapshot()
        self.assertEqual(snapshot['servers'][0]['health']['assessment']['code'],'filtering_off')
    def test_request_returns_without_waiting_for_network(self):
        entered=threading.Event();release=threading.Event()
        def slow():entered.set();release.wait(2)
        with patch.object(self.s,'check_connectivity',side_effect=slow):
            start=time.monotonic();self.assertTrue(self.s.request_connectivity()['ok'])
            self.assertLess(time.monotonic()-start,.5);self.assertTrue(entered.wait(1));release.set()
    def test_removed_server_incident_ends_as_unknown_not_recovered(self):
        self.check(BAD);self.s.config['servers']=[];self.s.config['adguard']['url']='';self.check(GOOD)
        self.assertTrue(all(e['end_reason']=='server_removed_or_disabled' for e in self.s.connectivity['incidents']))

class ConnectivityHTTPTests(unittest.TestCase):
    from test_hub import HubHTTPTests as _HTTP
    setUp=_HTTP.setUp
    tearDown=_HTTP.tearDown
    call=_HTTP.call
    def test_report_endpoint_is_authenticated_and_redacted(self):
        import urllib.request,urllib.error
        self.store.config['servers']=copy.deepcopy(SERVERS);self.store.config['primary_id']='one';self.store.align_primary()
        data=self.call('connectivity/export');raw=json.dumps(data)
        self.assertIn('samples',data);self.assertIn('limits',data)
        self.assertNotIn('one-secret',raw);self.assertNotIn(self.store.feed_token,raw)
        with self.assertRaises(urllib.error.HTTPError) as error:urllib.request.urlopen(self.base+'/api/connectivity/export')
        self.assertEqual(error.exception.code,401)
    def test_health_button_queues_and_report_reads_never_start_writes(self):
        with patch.object(self.store,'request_connectivity',return_value={'ok':True}),patch.object(self.store,'monitor') as monitor:
            self.assertTrue(self.call('hub/check',{})['ok'])
            self.call('connectivity/export')
        self.assertFalse(any(body is not None for _,_,body,_ in self.store.calls))
    def test_filter_diagnosis_uses_selected_replica(self):
        self.store.config['servers']=copy.deepcopy(SERVERS);self.store.config['primary_id']='one';self.store.align_primary()
        result=self.call('diagnostics?server=two')
        self.assertTrue(result['filtering']['enabled'])
        self.assertTrue(self.store.calls);self.assertTrue(all(sid=='two' for sid,_,_,_ in self.store.calls))
