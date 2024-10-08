# pylint: skip-file

import pytest
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaTransformationError
from sigma.backends.crowdsec import CrowdsecBackend
#import sigma.backends.


def test_crowdseec_webserver_field_mapping():
    assert CrowdsecBackend().convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: webserver
            detection:
                sel:
                  c-ip: '127.0.0.1'
                sel2:
                  s-sitename: 'foobar.com'
                sel3:
                  cs-method: 'GET'
                sel4:
                    cs-uri-query: 'TEST_PATTERN'
                condition: sel and sel2 and sel3 and sel4
        """), output_format="queryonly") == "evt.Meta.source_ip == '127.0.0.1' && evt.Parsed.target_fqdn == 'foobar.com' && evt.Meta.http_verb == 'GET' && evt.Parsed.http_args == 'TEST_PATTERN'"

# def test_crowdsec_aggreg():
#     assert CrowdsecBackend().convert(
#         SigmaCollection.from_yaml("""
#             title: Test
#             status: test
#             logsource:
#                 category: webserver
#             detection:
#                 sel:
#                   c-ip|endswith: 'toto'
#                 sel2:
#                   c-ip|contains|all:
#                     - 'titi1'
#                     - 'titi2'
#                 sel3:
#                   c-ip: 'tata'
#                 timeframe: 15m
#                 condition: sel and (sel2 or sel3)
#         """) 
#     ) == ['evt.Meta.source_ip == "toto"']


# def test_crowdsec_aggregbis():
#     assert CrowdsecBackend().convert(
#         SigmaCollection.from_yaml("""
#             title: Test
#             status: test
#             logsource:
#                 category: webserver
#             detection:
#                 selection:
#                     EventID: 4768
#                     Status: '0x12'
#                 filter_computer:
#                     TargetUserName|endswith: '$'
#                 timeframe: 24h
#                 condition: 'selection and not filter_computer | count(TargetUserName) by IpAddress > 10'
#         """) 
#     ) == ['evt.Meta.source_ip == "toto"']

# #count(UserName) by SourceWorkstation > 3

# def test_crowdsec_wtflol():
#     assert CrowdsecBackend().convert(
#         SigmaCollection.from_yaml("""
#             title: Test
#             status: test
#             logsource:
#                 category: webserver
#             detection:
#                 selection_execve:
#                     type: 'EXECVE'
#                 keywords_truncate:
#                     - 'truncate'
#                     - '-s'
#                 keywords_dd:
#                     - 'dd'
#                     - 'if='
#                 keywords_filter:
#                     - 'of='
#                 condition: selection_execve and (all of keywords_truncate or (all of keywords_dd and not keywords_filter))
#         """) 
#     ) == ['evt.Meta.source_ip == "toto"']

#     # type == 'execve' and ( all of ['truncate', '-s'] or ( all of ['dd', 'if='] and not ['of='] ) )
#     #['\'type\' == "EXECVE" AND (""truncate"" OR ""-s"" OR (""dd"" OR ""if="") AND NOT ""of="")']

# # detection:
# #     keywords_local_file_read:
# #         '|all':
# #             - 'FileNotFoundException'
# #             - '/../../..'
# #     condition: keywords_local_file_read