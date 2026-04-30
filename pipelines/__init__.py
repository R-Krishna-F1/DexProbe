"""
pipelines/ — One module per analysis pipeline.

Each pipeline receives an APKSession and returns list[Finding].
Nothing in pipelines/ touches the filesystem directly —
it reads paths from session.temp_dir.

Activated phases:
  Phase 2  → manifest.py
  Phase 3  → secrets.py
  Phase 4  → network.py
  Phase 5  → dynload.py
  Phase 6  → dependency.py
  Phase 7  → cve.py
  Phase 8  → reachability.py  (extends dependency + cve)
"""
