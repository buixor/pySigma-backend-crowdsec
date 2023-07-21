import pytest
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaTransformationError
import  sigma.backends.crowdsec as crowdsec
from sigma.backends.crowdsec import crowdsecBackend as backendx
#from sigma.backends.splunk import SplunkBackend as backendx
import sys
import pprint

#
process_start_rule_collection = SigmaCollection.load_ruleset([sys.argv[1]])



#pprint.pprint(process_start_rule_collection)
print(backendx().convert(rule_collection=process_start_rule_collection, output_format="default_yaml"))
