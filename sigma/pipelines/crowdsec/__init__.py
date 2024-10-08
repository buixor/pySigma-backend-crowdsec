"""Crowdsec pipeline for Sigma rules."""
from .crowdsec import crowdsec_pipeline

pipelines = {
    "crowdsec_pipeline": crowdsec_pipeline,
}
