import copy
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'robot_network'))
from common import validate,render_nft,render_return_nft,router_script,decide
from check import quantile
import agent
from unittest.mock import patch
from types import SimpleNamespace

CONFIG=json.loads((Path(__file__).resolve().parents[1]/'configs/site.example.json').read_text())

class ConfigTests(unittest.TestCase):
    def test_valid_example(self):self.assertEqual(validate(copy.deepcopy(CONFIG))['policy']['preferred'],'wifi')
    def test_interface_injection_rejected(self):
        c=copy.deepcopy(CONFIG);c['interfaces']['wifi']='wlan0; touch /tmp/x'
        with self.assertRaises(ValueError):validate(c)
    def test_overlap_rejected(self):
        c=copy.deepcopy(CONFIG);c['network']['chassis_cidr']=c['network']['debug_cidr']
        with self.assertRaises(ValueError):validate(c)
    def test_device_ip_collision_rejected(self):
        c=copy.deepcopy(CONFIG);c['network']['chassis_address']='192.168.10.10/24'
        with self.assertRaises(ValueError):validate(c)
    def test_duplicate_iface_rejected(self):
        c=copy.deepcopy(CONFIG);c['interfaces']['wifi']='eth0'
        with self.assertRaises(ValueError):validate(c)
    def test_original_direction_protects_debug_replies(self):
        r=render_nft(CONFIG)
        self.assertIn('ct direction original counter masquerade',r)
        self.assertNotIn('flush ruleset',r)
        self.assertIn('policy drop',r)
    def test_return_mark_happens_after_reverse_snat(self):
        r=render_return_nft(CONFIG)
        self.assertIn('priority -90',r)
        self.assertIn('ct direction reply',r)
        self.assertIn('0xff000000',r)
    def test_config_drives_other_interface_names(self):
        c=copy.deepcopy(CONFIG);c['interfaces']['cellular']='enp1s0'
        self.assertIn('enp1s0',render_nft(c));self.assertIn('enp1s0',render_return_nft(c))
    def test_transaction_injection_rejected(self):
        with self.assertRaises(ValueError):router_script(CONFIG,'apply','x; reboot')
    def test_router_backup_before_mutation(self):
        s=router_script(CONFIG,'apply','test-transaction')
        self.assertLess(s.index('cp -p /etc/config/network'),s.index('uci set network.lan.gateway'))
        self.assertIn('144',s);self.assertIn('COMMITTED',s)
    def test_percentile(self):
        self.assertEqual(quantile([0,10,20,30,40],.95),38)
        self.assertIsNone(quantile([],.95))
    def test_static_child_timer_is_ready_and_does_not_force_reinstall(self):
        def status(args,*rest):
            value='active' if args[1]=='is-active' else ('static' if args[2]=='robot-chassis-return-path.timer' else 'enabled')
            return SimpleNamespace(stdout=value+'\n')
        with patch.object(agent,'run',side_effect=status):self.assertTrue(agent.units_ready())

class PolicyTests(unittest.TestCase):
    def setUp(self):self.p=CONFIG['policy'];self.state={'active':'wifi','changed_at':0}
    def step(self,w,c,t):self.state=decide(self.state,w,c,t,self.p);return self.state['active']
    def test_three_failed_rounds(self):
        self.assertEqual(self.step(False,True,10),'wifi')
        self.assertEqual(self.step(False,True,20),'wifi')
        self.assertEqual(self.step(False,True,30),'cellular')
    def test_both_down_does_not_ping_pong(self):
        for t in range(10,100,10):self.assertEqual(self.step(False,False,t),'wifi')
        self.assertTrue(self.state['degraded'])
    def test_recovery_requires_count_and_hold(self):
        for t in [10,20,30]:self.step(False,True,t)
        for t in [40,50,60,70,80,90]:self.assertEqual(self.step(True,True,t),'cellular')
        self.assertEqual(self.step(True,True,151),'wifi')
    def test_recovery_counter_resets(self):
        self.state={'active':'cellular','changed_at':0}
        for t in [200,210,220]:self.step(True,True,t)
        self.step(False,True,230)
        self.assertEqual(self.step(True,True,240),'cellular')
    def test_dead_active_link_overrides_hold(self):
        self.state={'active':'cellular','changed_at':100}
        self.step(True,False,101);self.step(True,False,102)
        self.assertEqual(self.step(True,False,103),'wifi')
    def test_preferred_cellular_is_supported(self):
        self.p=dict(self.p,preferred='cellular');self.state={'active':'wifi','changed_at':0}
        for t in [121,122,123,124,125]:self.assertEqual(self.step(True,True,t),'wifi')
        self.assertEqual(self.step(True,True,126),'cellular')

if __name__=='__main__':unittest.main()
