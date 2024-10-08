import pytest
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaTransformationError
import  sigma.backends.crowdsec as crowdsec
from sigma.backends.crowdsec import CrowdsecBackend as backendx
#from sigma.backends.splunk import SplunkBackend as backendx
import sys
import pprint

#
process_start_rule_collection = SigmaCollection.load_ruleset([sys.argv[1]])



#pprint.(process_start_rule_collection)


for  rule in process_start_rule_collection.rules:
    for out in backendx().convert_rule(rule, "queryonly"):
        print (" -> ",out)
