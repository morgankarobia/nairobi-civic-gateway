# Nairobi Civic Gateway (`nairobi-civic-gateway`)

Evidence-led Reverse Engineering Audit (via [REA](https://github.com/morluto/rea)) and minimal-code Python 3.12 + SQLite reference architecture unifying Nairobi City County's five fragmented public portals.

## 1. Live REA Browser & Bundle Audit Findings (`evidence_manifest.json`)

| Portal | REA Evidence ID | Observed Stack | Key Finding |
| :--- | :--- | :--- | :--- |
| `nairobi.go.ke` | `ev_fe4167049c2f99d1842effb6b7f86c2c9674b1a3c00088df2798c5b72faa4ddb` | WordPress + Download Manager (`wpdm 3.2.54`) | Static document publishing; external Google Forms complaint link |
| `nairobiservices.go.ke` | `ev_fbf70e6449640f776ce62af9174b43cd63fcdb1c3c6eab76321ceec9a00d65ca` | Next.js SPA (`/_next/static/chunks/`) | Separate account & revenue portal (NairobiPay) |
| `edev.nairobiservices.go.ke` | `ev_8b0d1e3c40e7dda2123c40e93e88e1227cd08ef0d107474cafce80b19d132075` | React Webpack SPA (`main.a146491a.chunk.js`) | Separate physical planning portal (NairobiPlan) |
| `husikanai.nairobi.go.ke` | `ev_f470eb42627e4a09f2bd5d391e4299f01b161abf09146939a39ad37a3556ac5a` | Ruby on Rails / CONSUL Democracy | Bilingual support (`?locale=en`, `?locale=sw-KE`) & ICRMS project records |
| `nairobiassembly.go.ke` | `ev_c9ca89b0d1264ac7ce280a6b0c68c096eefa3c24dcc83e5292845aeb89133ca2` | WordPress (`/ncca/` theme `nrbca`) | Legislative bills, budgets, and committee reports |

## 2. Level 5 Algorithmic Modules (`src/nairobi_civic_gateway.py`)
- **Inverted Index + Okapi BM25 Service Discovery:** Maps natural-language citizen queries and synonyms across all 5 portals with 2025 Service Charter SLAs.
- **Deterministic Finite-State Machine (FSM) & Priority Queue ($P = 0.35U + 0.25I + 0.25D + 0.15A$):** Replaces un-tracked complaint forms with SLA-tracked case routing and hard emergency overrides.
- **SHA-256 Hash-Chained Audit Ledger:** Tamper-evident SQLite state-transition log.
- **Multi-Source Project Discrepancy Register:** Preserves conflicting public records side-by-side (e.g., KSh 847.23M ICRMS/ERP `18%` HusikaNai record vs. `37%` Controller of Budget review).

## Quick Start
```bash
python3 src/nairobi_civic_gateway.py
python3 -m unittest discover -s tests -v
