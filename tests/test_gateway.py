import unittest, sys
sys.path.insert(0, "src")
from nairobi_civic_gateway import BM25ServiceSearch, SERVICES, CivicGatewayDB

class TestNairobiCivicGateway(unittest.TestCase):
    def test_bm25_synonym_routing(self):
        engine = BM25ServiceSearch(SERVICES)
        res = engine.search("How do I get permission to construct a building?", top_k=1)
        self.assertEqual(res[0]["portal"], "NairobiPlan")
        self.assertEqual(res[0]["url"], "https://edev.nairobiservices.go.ke/")

    def test_fsm_priority_and_hash_chain(self):
        db = CivicGatewayDB()
        db.submit_complaint("NCC-1", "Embakasi", "Uncollected garbage", age_days=1)
        db.submit_complaint("NCC-2", "CBD", "Open manhole hazard", age_days=0)
        q = db.priority_dispatch_queue()
        self.assertEqual(q[0]["case_id"], "NCC-2")
        self.assertEqual(q[0]["priority"], 1.0)
        db.transition_complaint("NCC-1", "ACKNOWLEDGED", "officer-1")
        with self.assertRaises(ValueError):
            db.transition_complaint("NCC-1", "VERIFIED", "officer-1")
        self.assertTrue(db.verify_audit_chain())

    def test_icrms_discrepancy_preservation(self):
        db = CivicGatewayDB()
        rep = db.seed_icrms_project()
        self.assertTrue(rep["discrepancy_detected"])
        self.assertEqual(rep["progress_spread_pct"], "18% vs 37%")

if __name__ == "__main__":
    unittest.main()
