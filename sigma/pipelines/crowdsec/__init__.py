from .crowdsec import crowdsec_pipeline
# TODO: add all pipelines that should be exposed to the user of your backend in the import statement above.

pipelines = {
    "crowdsec_pipeline": crowdsec_pipeline,   # TODO: adapt identifier to something approproiate
}