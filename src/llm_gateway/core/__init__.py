"""Wiring: builds the gateway's parts from the settings (factory.py).

Phase 13 adds the request pipeline that calls the AI provider. (The text
normalizer lives in detectors/normalizer.py, because every detector needs it
and detectors may not import from core.)
"""
