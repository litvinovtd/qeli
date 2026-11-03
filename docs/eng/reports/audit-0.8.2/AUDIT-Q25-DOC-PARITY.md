# Q25-F200 — audit report structure and language parity

Status: 1 October 2026; documentation checker PASS. Product code was unchanged.

Before this change, `scripts/check_docs.py` reported 61 findings: 32 reports lacked direct links in their language indexes, 3 links in the English D08 register were broken, and 26 Russian D08 reports lacked English counterparts. The three paths were corrected, existing reports received direct index entries, and substantive English versions of Q25-F164–F189 were written. The translations retain base SHAs, observed behavior, validation and unavailable-platform limitations. JSON is described only as an internal container; user config remains INI.

After the change, `python scripts/check_docs.py` checked 494 Markdown files and all 9 checks passed (`links`, `index`, `parity`, `config`, `source`, `placeholder`, `version`, `anchors`, `sync`). An automated comparison confirmed the presence and matching base SHAs of all 26 pairs. D15 remains IN_PROGRESS for reconciling older evidence and patch applicability; a green checker alone does not validate D08/D12 runtime work.
