"""Crowdsec backend for Sigma rules."""
from .crowdsec import CrowdsecBackend

backends = {
    "crowdsec": CrowdsecBackend,
}
