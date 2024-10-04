#from sigma.pipelines.common import  logsource_webserver, webserver_logsource_mapping
from sigma.processing.transformations import AddConditionTransformation, FieldMappingTransformation, DetectionItemFailureTransformation, RuleFailureTransformation, SetStateTransformation
from sigma.processing.conditions import LogsourceCondition, IncludeFieldCondition, ExcludeFieldCondition, RuleProcessingItemAppliedCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.pipelines.base import Pipeline

# TODO: the following code is just an example extend/adapt as required.
# See https://sigmahq-pysigma.readthedocs.io/en/latest/Processing_Pipelines.html for further documentation.

@Pipeline
def crowdsec_pipeline() -> ProcessingPipeline:        # Processing pipelines should be defined as functions that return a ProcessingPipeline object.
    return ProcessingPipeline(
        name="crowdsec webserver pipeline",
        allowed_backends={"crowdsecBackend"},                                               # Set of identifiers of backends (from the backends mapping) that are allowed to use this processing pipeline. This can be used by frontends like Sigma CLI to warn the user about inappropriate usage.
        priority=20,            # The priority defines the order pipelines are applied. See documentation for common values.
        items=[
        
            ProcessingItem(     # This is an example for processing items generated from the mapping above.
                identifier="crowdsec_webserver_fieldmapping",
                rule_conditions=[LogsourceCondition(category="webserver",)],
                transformation=FieldMappingTransformation({
                    "date": "evt.StrTime",
                    "time": "evt.StrTime",
                    "c-ip": "evt.Meta.source_ip",
                    "cs-username": "evt.Parsed.remote_user",
                    "s-sitename": "evt.Parsed.target_fqdn",
#                    "s-computername": "N/A", might only be present from web logs over syslog?
#                    "s-ip": "N/A", might only be present from web logs over syslog?
#                    "s-port": "N/A", might only be present from web logs over syslog?
                    "cs-method": "evt.Meta.http_verb",
                    "cs-uri-stem": "evt.Meta.http_path",
                    "cs-uri-query": "evt.Parsed.http_args",
                    "sc-status": "int(evt.Meta.http_status)",
                    "c-win23-status": "int(evt.Meta.http_status)", #same as sc-status
                    "sc-bytes": "int(evt.Parsed.body_bytes_sent)",
                    "cs-bytes": "int(evt.Parsed.request_length)",
                    "time-taken": "evt.Parsed.request_time", #no part of default logging formats
                    "cs-version": "evt.Parsed.http_version",
                    "cs-host": "evt.Parsed.target_fqdn",
                    "cs-user-agent": "evt.Meta.http_user_agent",
#                   "cs-cookie": "N/A", no part of default logging formats
                   "cs-referer": "evt.Parsed.http_referer",
                })
            ),

    #             "Computer": "Registry.dest",
    # "Details": "Registry.registry_value_data",
    # "EventType": "Registry.action", # EventType: DeleteKey is parsed to action: deleted
    # "Image": "Registry.process_path",
    # "ProcessGuid": "Registry.process_guid",
    # "ProcessId": "Registry.process_id",
    # "TargetObject": "Registry.registry_key_name",

            ProcessingItem(     # This is an example for processing items generated from the mapping above.
                identifier="crowdsec_windows_process_creation_fieldmapping",
                rule_conditions=[LogsourceCondition(category="process_creation",product="windows",)],
                transformation=FieldMappingTransformation({
                    "Computer" : "evt.Parsed.Computer",
                    
                })
            ),
            ProcessingItem(     # This is an example for processing items generated from the mapping above.
                identifier="crowdsec_windows_registry_add_fieldmapping",
                rule_conditions=[LogsourceCondition(category="process_creation",product="windows",)],
                transformation=FieldMappingTransformation({
                    #"EventID": "int(evt.Parsed.EventID)",
                    "Company": "evt.Parsed.Company",
                    "OriginalFileName" : "evt.Parsed.OriginalFileName",
                    "UtcTime": "evt.StrTime",
                    "ProcessGuid": "evt.Parsed.ProcessGuid",
                    "ProcessId": "int(evt.Parsed.ProcessId)",
                    "Image": "evt.Parsed.Image",
                    "FileVersion": "evt.Parsed.FileVersion",
                    "Description": "evt.Parsed.Description",
                    "CommandLine": "evt.Parsed.CommandLine",
                    "CurrentDirectory": "evt.Parsed.CurrentDirectory",
                    "User": "evt.Parsed.User",
                    "LogonGuid": "evt.Parsed.LogonGuid",
                    "LogonId": "int(evt.Parsed.LogonId)",
                    "TerminalSessionId": "evt.Parsed.TerminalSessionId",
                    "IntegrityLevel": "evt.Parsed.IntegrityLevel",
                    "ParentProcessGuid": "evt.Parsed.ParentProcessGuid",
                    "ParentProcessId": "int(evt.Parsed.ParentProcessId)",
                    "ParentImage": "evt.Parsed.ParentImage",
                    "ParentCommandLine": "evt.Parsed.ParentCommandLine",
                    "Product": "evt.Parsed.Product",
                    "Hashes": "evt.Parsed.Hashes",
                    "ParentUser": "evt.Parsed.ParentUser",
                    "Imphash": "evt.Parsed.Imphash",
                    "Provider_Name": "evt.Parsed.ProviderName",
                    #taxonomy says it's imphash, but rules seem to use ImpHash
                    "imphash": "evt.Parsed.Imphash",                    
                    "md5": "evt.Parsed.md5",
                    "sha1": "evt.Parsed.sha1",
                    "sha256": "evt.Parsed.sha256",

                })
            ),
            ProcessingItem(     # This is an example for processing items generated from the mapping above.
                identifier="crowdsec_webproxy_fieldmapping",
                rule_conditions=[LogsourceCondition(category="proxy")],
                transformation=FieldMappingTransformation({
                    "c-uri": "evt.Parsed.uri",
                })
            ),
            # ProcessingItem(
            #     identifier="crowdsec_rule_not_supported",
            #     rule_condition_linking=any,
            #     transformation=RuleFailureTransformation("Rule type not yet supported by crowdsec backend!"),
            #     rule_condition_negation=True,
            #     rule_conditions=[
            #         RuleProcessingItemAppliedCondition("crowdsec_webserver_fieldmapping"),
            #         RuleProcessingItemAppliedCondition("crowdsec_windows_fieldmapping")
            #     ],
            # ),
        ],
    )
