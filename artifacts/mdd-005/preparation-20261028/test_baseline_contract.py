"""Finite certificate/engine-pin contract tests; never analysis measurements."""
import copy
import json
from pathlib import Path
import unittest
import baseline_driver as driver

ROOT=driver.ROOT


class Contracts(unittest.TestCase):
    def evidence(self):
        data={key:[] for key in driver.EVIDENCE_KEYS}
        data['features']={str(n):{'status':'MISSING','detail':'contract fixture only'} for n in range(27)}
        data['class_records']=[{'value':None},{'value':''},{'value':None}]
        return data

    def certificate(self):
        return {'complete':True,'evidence_group_count':20,'feature_count':27,'fallback_count':0,
            'output_fully_materialized':True,'more_available':False,'truncated':False,
            'input_sha256':'a'*64,'reference_source_commit':driver.REFERENCE_COMMIT,'tools':{'fixture':'hash'},
            'groups':driver.canonical_groups(self.evidence())}

    def test_multiset_keeps_duplicates_and_null_identity(self):
        left=self.evidence();right=copy.deepcopy(left);right['class_records'].reverse()
        self.assertEqual(driver.canonical_groups(left),driver.canonical_groups(right))
        right['class_records']=[{'value':None},{'value':''},{'value':''}]
        self.assertNotEqual(driver.canonical_groups(left),driver.canonical_groups(right))

    def test_all_twenty_fields_and_completion_axes_required(self):
        good=self.certificate()
        self.assertTrue(driver.compare_certificates(good,copy.deepcopy(good))['all_equal'])
        for key,value in [('complete',False),('fallback_count',1),('more_available',True),
            ('truncated',True),('output_fully_materialized',False),('feature_count',0),('evidence_group_count',19)]:
            broken=copy.deepcopy(good);broken[key]=value
            with self.subTest(key=key),self.assertRaises(RuntimeError):driver.compare_certificates(good,broken)
        broken=copy.deepcopy(good);broken['groups'].pop('limitations')
        with self.assertRaises(RuntimeError):driver.compare_certificates(good,broken)

    def test_source_input_mismatch_and_value_drift_not_equivalent(self):
        good=self.certificate();broken=copy.deepcopy(good);broken['input_sha256']='b'*64
        with self.assertRaises(RuntimeError):driver.compare_certificates(good,broken)
        broken=copy.deepcopy(good);broken['groups']['features']['sha256']='changed'
        self.assertEqual(driver.compare_certificates(good,broken)['mismatch_groups'],['features'])

    def test_a1_pin_preserves_real_identity_and_rejects_a0(self):
        plan=driver.read(ROOT/'benchmarks/baseline-manifest.json');selected=driver.variant(plan,'A1')
        proxy=driver.pin_provider(None,selected)
        self.assertEqual(proxy.status()['version'],'0.1.1')
        self.assertEqual(proxy.status()['sha256'],selected['engine_binary']['sha256'])
        with self.assertRaises(RuntimeError):proxy.verify(driver.variant(plan,'A0')['engine_binary']['path'])
        with self.assertRaises(RuntimeError):proxy.install()


if __name__=='__main__':unittest.main(verbosity=2)
