"""The gateway pipeline that runs every step in order.

Phase 8 adds the pipeline. (The text normalizer lives in detectors/normalizer.py,
because every detector needs it and detectors may not import from core.)
"""
