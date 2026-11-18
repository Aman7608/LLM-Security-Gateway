"""The policy engine turns findings into a decision (allow, warn, redact, block).

schema.py  the policy file format and every check made when loading it
store.py   the active policy, its version history, and safe changes
engine.py  PolicyEngine.decide(): findings in, one structured Decision out
"""
