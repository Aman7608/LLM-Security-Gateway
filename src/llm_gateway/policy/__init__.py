"""The policy engine turns findings into a decision (allow, warn, redact, block).

Phase 8 added the first version (engine.py): ordered rules from
config/policy.yaml. Phase 9 adds risk scoring, policy versions and reloading.
"""
