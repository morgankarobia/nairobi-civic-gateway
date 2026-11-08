#!/usr/bin/env python3
"""
Nairobi City County — Unified Civic Gateway & REA Evidence Engine
Zero-bloat, dependency-free Python 3.12 + SQLite implementation of:
  1. REA Browser Evidence Parser (Levels 1-4: DOM, Scripts, Destinations, Bundles)
  2. Inverted Index + Okapi BM25 Service Discovery Engine (2025 Service Charter SLAs)
  3. Rule Engine + Priority Queue Complaint Router (P = 0.35U + 0.25I + 0.25D + 0.15A)
  4. Deterministic Finite-State Machine (FSM) + SHA-256 Hash-Chained Audit Ledger
  5. Multi-Source Evidence-Linked Project Register (ICRMS/ERP Discrepancy Tracker)
"""
from __future__ import annotations
import glob, hashlib, heapq, json, math, os, re, sqlite3
from datetime import datetime, timezone

# --- 1. INVERTED INDEX + BM25 SERVICE DISCOVERY (2025 SERVICE CHARTER) ---
SYNONYMS = {
    "construct": "building", "construction": "building", "architect": "building",
    "renovate": "building", "renovation": "building", "plan": "planning",
    "garbage": "waste", "dumping": "waste", "rubbish": "waste", "trash": "waste",
    "sewer": "drainage", "flood": "drainage", "blocked": "drainage",
    "shop": "business", "license": "permit", "licence": "permit", "sbp": "permit",
    "hawker": "vending", "stall": "vending", "kiosk": "vending",
    "land": "rates", "property": "rates", "plot": "rates",
    "car": "parking", "matatu": "parking", "clamp": "parking",
    "budget": "legislation", "bill": "legislation", "mca": "legislation",
}
STOPWORDS = {"how", "do", "i", "get", "to", "a", "an", "the", "in", "for", "of", "where", "can", "my", "is", "on"}

SERVICES = [
    {"id": "SRV-PERMIT", "title": "Single Business Permit & Trade Licensing", "sector": "Trade & Markets",
     "portal": "NairobiPay", "url": "https://nairobiservices.go.ke/", "sla_days": 3, "charter_target": "100% within 3 days",
     "keywords": "business permit trade license shop commercial enterprise renewal fee"},
    {"id": "SRV-VENDING", "title": "Hawking & Street Vending Space Allocation", "sector": "Trade & Markets",
     "portal": "NairobiPay", "url": "https://nairobiservices.go.ke/", "sla_days": 7, "charter_target": "95% within 7 days",
     "keywords": "hawking vending stall space market allocation informal trader"},
    {"id": "SRV-PLAN", "title": "Building Permit & Physical Development Approval", "sector": "Physical Planning",
     "portal": "NairobiPlan", "url": "https://edev.nairobiservices.go.ke/", "sla_days": 14, "charter_target": "Statutory review",
     "keywords": "building permit physical planning construction structural approval renovation land development"},
    {"id": "SRV-RATES", "title": "Land Rates, Property Search & Parking eServices", "sector": "Revenue & Finance",
     "portal": "NairobiPay", "url": "https://nairobiservices.go.ke/", "sla_days": 1, "charter_target": "Instant e-receipt",
     "keywords": "land rates property payment parking daily seasonal receipt revenue"},
    {"id": "SRV-COMPLAINT", "title": "Public Complaint & Environmental Service Request", "sector": "Environment & Public Works",
     "portal": "Nairobi Civic Gateway (Replaces Google Forms)", "url": "https://nairobi.go.ke/", "sla_days": 7,
     "charter_target": "90% resolution and feedback within 7 days",
     "keywords": "complaint report waste uncollected garbage illegal dumping blocked drainage road pothole sanitation"},
    {"id": "SRV-PARTICIPATE", "title": "Public Participation, Ward Projects & Petitions", "sector": "Public Participation (CONSUL)",
     "portal": "HusikaNai", "url": "https://husikanai.nairobi.go.ke/", "sla_days": 14, "charter_target": "Public consultation window",
     "keywords": "participate participation vote ward project budget proposal petition policy husikanai"},
    {"id": "SRV-ASSEMBLY", "title": "County Laws, Budgets, Hansard & Committee Reports", "sector": "County Assembly",
     "portal": "Nairobi County Assembly", "url": "https://nairobiassembly.go.ke/", "sla_days": 1, "charter_target": "Public access",
     "keywords": "assembly legislation laws bills budget controller audit report papers laid"},
]

def tokenize(text: str) -> list[str]:
    words = re.findall(r"[a-z0-9]+", text.lower())
    return [SYNONYMS.get(w, w) for w in words if w not in STOPWORDS]

class BM25ServiceSearch:
    def __init__(self, docs: list[dict], k1: float = 1.5, b: float = 0.75):
        self.docs, self.k1, self.b = docs, k1, b
        self.corpus = [tokenize(f"{d['title']} {d['sector']} {d['keywords']}") for d in docs]
        self.doc_lens = [len(c) for c in self.corpus]
        self.avgdl = sum(self.doc_lens) / max(len(self.corpus), 1)
        self.inverted: dict[str, dict[int, int]] = {}
        for idx, tokens in enumerate(self.corpus):
            for t in tokens:
                self.inverted.setdefault(t, {})[idx] = self.inverted.get(t, {}).get(idx, 0) + 1

    def search(self, query: str, top_k: int = 3) -> list[dict]:
        q_tokens = tokenize(query)
        scores = [0.0] * len(self.docs)
        n_docs = len(self.docs)
        for t in q_tokens:
            postings = self.inverted.get(t, {})
            df = len(postings)
            if not df:
                continue
            idf = math.log(1.0 + (n_docs - df + 0.5) / (df + 0.5))
            for doc_idx, tf in postings.items():
                dl = self.doc_lens[doc_idx]
                denom = tf + self.k1 * (1.0 - self.b + self.b * (dl / self.avgdl))
                scores[doc_idx] += idf * ((tf * (self.k1 + 1.0)) / denom)
        ranked = sorted(enumerate(scores), key=lambda x: x[1], reverse=True)
        return [{**self.docs[i], "bm25_score": round(s, 4)} for i, s in ranked if s > 0][:top_k]

# --- 2. FINITE-STATE MACHINE + PRIORITY QUEUE + SHA-256 HASH CHAIN ---
VALID_TRANSITIONS: dict[str, set[str]] = {
    "SUBMITTED": {"ACKNOWLEDGED"},
    "ACKNOWLEDGED": {"ASSIGNED"},
    "ASSIGNED": {"IN_PROGRESS"},
    "IN_PROGRESS": {"RESOLVED", "ESCALATED"},
    "ESCALATED": {"IN_PROGRESS", "RESOLVED"},
    "RESOLVED": {"VERIFIED", "REOPENED"},
    "REOPENED": {"ASSIGNED", "IN_PROGRESS"},
    "VERIFIED": set(),
}

ROUTING_RULES = [
    (re.compile(r"fire|collapse|ambulanc|electrocut|burst main|open manhole", re.I), "Emergency Services", 1.0, 1.0, True),
    (re.compile(r"drain|sewer|flood|culvert|stormwater", re.I), "Public Works & Drainage", 0.85, 0.80, False),
    (re.compile(r"garbage|dump|waste|sanitation|litter", re.I), "Environment & Sanitation", 0.70, 0.75, False),
    (re.compile(r"pothole|road|streetlight|bridge", re.I), "Roads & Transport", 0.65, 0.70, False),
]

def compute_priority(urgency: float, impact: float, age_days: float, sla_days: float = 7.0, emergency: bool = False) -> float:
    if emergency:
        return 1.0
    u, i = max(0.0, min(1.0, urgency)), max(0.0, min(1.0, impact))
    d = max(0.0, min(1.0, age_days / max(sla_days, 1.0)))
    a = max(0.0, min(1.0, age_days / 14.0))
    return round(0.35 * u + 0.25 * i + 0.25 * d + 0.15 * a, 4)

class CivicGatewayDB:
    def __init__(self, db_path: str = ":memory:"):
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS complaints (
                case_id TEXT PRIMARY KEY, category TEXT NOT NULL, department TEXT NOT NULL,
                ward TEXT NOT NULL, description TEXT NOT NULL, state TEXT NOT NULL,
                priority REAL NOT NULL, emergency INTEGER NOT NULL, sla_days INTEGER NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_chain (
                seq INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT NOT NULL,
                from_state TEXT NOT NULL, to_state TEXT NOT NULL, actor TEXT NOT NULL,
                timestamp TEXT NOT NULL, prev_hash TEXT NOT NULL, record_hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS projects (
                project_ref TEXT PRIMARY KEY, name TEXT NOT NULL, sector TEXT NOT NULL,
                approved_budget_kes REAL NOT NULL, status TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS project_observations (
                obs_id INTEGER PRIMARY KEY AUTOINCREMENT, project_ref TEXT NOT NULL,
                source_name TEXT NOT NULL, source_url TEXT NOT NULL, observed_date TEXT NOT NULL,
                reported_spend_kes REAL, reported_progress_pct REAL NOT NULL, notes TEXT NOT NULL
            );
        """)

    def _append_audit(self, case_id: str, from_state: str, to_state: str, actor: str) -> str:
        row = self.conn.execute("SELECT record_hash FROM audit_chain ORDER BY seq DESC LIMIT 1").fetchone()
        prev_hash = row["record_hash"] if row else "0" * 64
        ts = datetime.now(timezone.utc).isoformat()
        payload = f"{prev_hash}|{case_id}|{from_state}|{to_state}|{actor}|{ts}"
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        self.conn.execute(
            "INSERT INTO audit_chain (case_id, from_state, to_state, actor, timestamp, prev_hash, record_hash) VALUES (?,?,?,?,?,?,?)",
            (case_id, from_state, to_state, actor, ts, prev_hash, digest),
        )
        return digest

    def submit_complaint(self, case_id: str, ward: str, description: str, age_days: float = 0.0) -> dict:
        dept, u, imp, emerg = "General Citizen Services", 0.5, 0.5, False
        for pattern, r_dept, r_u, r_imp, r_emerg in ROUTING_RULES:
            if pattern.search(description):
                dept, u, imp, emerg = r_dept, r_u, r_imp, r_emerg
                break
        prio = compute_priority(u, imp, age_days=age_days, sla_days=7.0, emergency=emerg)
        ts = datetime.now(timezone.utc).isoformat()
        self.conn.execute(
            "INSERT INTO complaints VALUES (?,?,?,?,?,?,?,?,?,?)",
            (case_id, dept, dept, ward, description, "SUBMITTED", prio, int(emerg), 7, ts),
        )
        digest = self._append_audit(case_id, "NONE", "SUBMITTED", "citizen-portal")
        self.conn.commit()
        return {"case_id": case_id, "department": dept, "state": "SUBMITTED", "priority": prio, "emergency": emerg, "audit_hash": digest}

    def transition_complaint(self, case_id: str, to_state: str, actor: str) -> str:
        row = self.conn.execute("SELECT state FROM complaints WHERE case_id = ?", (case_id,)).fetchone()
        if not row:
            raise KeyError(f"Unknown case_id: {case_id}")
        cur = row["state"]
        if to_state not in VALID_TRANSITIONS.get(cur, set()):
            raise ValueError(f"Illegal FSM transition: {cur} -> {to_state}")
        self.conn.execute("UPDATE complaints SET state = ? WHERE case_id = ?", (to_state, case_id))
        digest = self._append_audit(case_id, cur, to_state, actor)
        self.conn.commit()
        return digest

    def verify_audit_chain(self) -> bool:
        rows = self.conn.execute("SELECT * FROM audit_chain ORDER BY seq ASC").fetchall()
        expected_prev = "0" * 64
        for r in rows:
            if r["prev_hash"] != expected_prev:
                return False
            payload = f"{r['prev_hash']}|{r['case_id']}|{r['from_state']}|{r['to_state']}|{r['actor']}|{r['timestamp']}"
            if hashlib.sha256(payload.encode("utf-8")).hexdigest() != r["record_hash"]:
                return False
            expected_prev = r["record_hash"]
        return True

    def priority_dispatch_queue(self) -> list[dict]:
        rows = self.conn.execute("SELECT * FROM complaints WHERE state != 'VERIFIED'").fetchall()
        heap = [(-r["priority"], r["case_id"], dict(r)) for r in rows]
        heapq.heapify(heap)
        out = []
        while heap:
            _, _, item = heapq.heappop(heap)
            out.append(item)
        return out

    def seed_icrms_project(self) -> dict:
        self.conn.execute(
            "INSERT OR REPLACE INTO projects VALUES (?,?,?,?,?)",
            ("NCC-ICRMS-2026", "Integrated County Revenue Management System / ERP (ICRMS)",
             "Innovation & Digital Economy", 847_230_000.0, "DELAYED"),
        )
        self.conn.execute("DELETE FROM project_observations WHERE project_ref = 'NCC-ICRMS-2026'")
        self.conn.execute(
            "INSERT INTO project_observations (project_ref, source_name, source_url, observed_date, reported_spend_kes, reported_progress_pct, notes) VALUES (?,?,?,?,?,?,?)",
            ("NCC-ICRMS-2026", "HusikaNai Public Project Record", "https://husikanai.nairobi.go.ke/", "2026-10-16", 150_000_000.0, 18.0,
             "Needs assessment, systems audit, upgrades, configuration, data migration, development and testing."),
        )
        self.conn.execute(
            "INSERT INTO project_observations (project_ref, source_name, source_url, observed_date, reported_spend_kes, reported_progress_pct, notes) VALUES (?,?,?,?,?,?,?)",
            ("NCC-ICRMS-2026", "Controller of Budget Review (Cited Oct 2026)", "https://nairobiassembly.go.ke/", "2026-10-20", 150_000_000.0, 37.0,
             "Independent review figure; preserved separately rather than averaged with HusikaNai 18% figure."),
        )
        self.conn.commit()
        obs = [dict(r) for r in self.conn.execute("SELECT * FROM project_observations WHERE project_ref = 'NCC-ICRMS-2026'").fetchall()]
        pcts = [o["reported_progress_pct"] for o in obs]
        return {"project_ref": "NCC-ICRMS-2026", "approved_budget_kes": 847_230_000.0,
                "discrepancy_detected": (max(pcts) - min(pcts)) > 5.0,
                "progress_spread_pct": f"{min(pcts):.0f}% vs {max(pcts):.0f}%", "observations": obs}

# --- 3. REA BROWSER EVIDENCE AUDITOR (READS evidence/*.json SAFELY) ---
def audit_rea_evidence(evidence_dir: str = "evidence") -> list[dict]:
    summaries = []
    for path in sorted(glob.glob(os.path.join(evidence_dir, "*.json"))):
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            continue
        if "evidence_id" not in data:
            continue
        res = data.get("normalized_result") or {}
        target = res.get("target") or {}
        scripts_obj = res.get("scripts")
        if isinstance(scripts_obj, dict):
            script_list = scripts_obj.get("items") or scripts_obj.get("scripts") or list(scripts_obj.values())
        elif isinstance(scripts_obj, list):
            script_list = scripts_obj
        else:
            script_list = []
        script_urls = [s.get("url") for s in script_list if isinstance(s, dict) and s.get("url")]
        urls_found = set(re.findall(r"https?://[^\s\"'<>\\]+", json.dumps(res)))
        external_portals = sorted(
            u for u in urls_found
            if any(k in u.lower() for k in ("forms.gle", "docs.google.com/forms", "nairobiservices", "husikanai", "nairobiassembly", "ecitizen"))
        )
        summaries.append({
            "file": os.path.basename(path),
            "evidence_id": data["evidence_id"],
            "operation": data.get("operation"),
            "url": target.get("url") or (res.get("page") or {}).get("url"),
            "title": target.get("title") or (res.get("page") or {}).get("title"),
            "script_count": len(script_urls) or (len(scripts_obj) if isinstance(scripts_obj, dict) else 0),
            "sample_scripts": script_urls[:4],
            "cross_portal_and_form_links": external_portals[:8],
        })
    return summaries

if __name__ == "__main__":
    print("=== 1. REA LIVE EVIDENCE AUDIT ===")
    ev = audit_rea_evidence("evidence")
    if ev:
        for item in ev:
            print(f"• {item['file']} ({item['operation']}) -> {item['title'] or item['url']}")
            print(f"  Evidence ID : {item['evidence_id']}")
            print(f"  Scripts     : {item['script_count']}")
            for s_url in item["sample_scripts"]:
                print(f"    script    : {s_url}")
            for link in item["cross_portal_and_form_links"][:5]:
                print(f"    linked    : {link}")
    else:
        print("  (Run inside ~/rea-work/nairobi-civic-gateway to parse evidence/*.json)")

    print("\n=== 2. BM25 SERVICE DISCOVERY TEST ===")
    engine = BM25ServiceSearch(SERVICES)
    for q in [
        "How do I get permission to construct a building?",
        "report uncollected garbage and blocked drainage",
        "pay land rates and daily parking",
    ]:
        top = engine.search(q, top_k=1)[0]
        print(f"  Query : '{q}'")
        print(f"  Match : {top['title']} [{top['portal']} -> {top['url']}] (BM25={top['bm25_score']}, SLA={top['charter_target']})")

    print("\n=== 3. FSM + PRIORITY QUEUE + SHA-256 AUDIT CHAIN TEST ===")
    db = CivicGatewayDB()
    db.submit_complaint("NCC-2026-001", "Embakasi", "Uncollected garbage near market", age_days=2)
    db.submit_complaint("NCC-2026-002", "Starehe", "Blocked drainage causing severe road flooding in Eastlands", age_days=5)
    db.submit_complaint("NCC-2026-003", "CBD", "Open manhole and burst main hazard on pedestrian walkway", age_days=0)
    db.transition_complaint("NCC-2026-002", "ACKNOWLEDGED", "dispatch-bot")
    db.transition_complaint("NCC-2026-002", "ASSIGNED", "eng-oduor")
    for rank, c in enumerate(db.priority_dispatch_queue(), 1):
        print(f"  #{rank} [{c['case_id']}] P={c['priority']:.4f} (Emergency={bool(c['emergency'])}) | {c['department']} | State={c['state']}")
    print(f"  Audit Chain Cryptographic Integrity Verified: {db.verify_audit_chain()}")

    print("\n=== 4. ICRMS / ERP MULTI-SOURCE DISCREPANCY REGISTER ===")
    icrms = db.seed_icrms_project()
    print(f"  Project: {icrms['project_ref']} | Discrepancy Flagged: {icrms['discrepancy_detected']} ({icrms['progress_spread_pct']})")