"""The web API: routes, API key checks, rate limits, error format and middleware.

The routes stay thin. The real work (checking, calling the AI, logging)
happens in core/gateway.py, which knows nothing about HTTP.
"""
