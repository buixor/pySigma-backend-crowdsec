# pylint: skip-file

import pytest
from sigma.collection import SigmaCollection
from sigma.backends.crowdsec import CrowdsecBackend

@pytest.fixture
def crowdsec_backend():
    return CrowdsecBackend()

# # TODO: implement tests for some basic queries and their expected results.
def test_crowdsec_and_expression(crowdsec_backend : CrowdsecBackend):
    assert crowdsec_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """),
    output_format="queryonly") == "fieldA == 'valueA' && fieldB == 'valueB'"

def test_crowdsec_or_expression(crowdsec_backend : CrowdsecBackend):
    assert crowdsec_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA
                sel2:
                    fieldB: valueB
                condition: 1 of sel*
        """),
    output_format="queryonly") == "fieldA == 'valueA' || fieldB == 'valueB'"

def test_crowdsec_and_or_expression(crowdsec_backend : CrowdsecBackend):
    assert crowdsec_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA1
                        - valueA2
                    fieldB:
                        - valueB1
                        - valueB2
                condition: sel
        """),
    output_format="queryonly") == "(fieldA in ['valueA1', 'valueA2']) && (fieldB in ['valueB1', 'valueB2'])"

def test_crowdsec_or_and_expression(crowdsec_backend : CrowdsecBackend):
    assert crowdsec_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA1
                    fieldB: valueB1
                sel2:
                    fieldA: valueA2
                    fieldB: valueB2
                condition: 1 of sel*
        """),
    output_format="queryonly") == "fieldA == 'valueA1' && fieldB == 'valueB1' || fieldA == 'valueA2' && fieldB == 'valueB2'"

def test_crowdsec_in_expression(crowdsec_backend : CrowdsecBackend):
    assert crowdsec_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA
                        - valueB
                        - valueC*
                condition: sel
        """),
    output_format="queryonly") == "fieldA == 'valueA' || fieldA == 'valueB' || fieldA startsWith 'valueC'"

def test_crowdsec_regex_query(crowdsec_backend : CrowdsecBackend):
    assert crowdsec_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar
                    fieldB: foo
                condition: sel
        """),
    output_format="queryonly") == "fieldA matches 'foo.*bar' && fieldB == 'foo'"

def test_crowdsec_cidr_query(crowdsec_backend : CrowdsecBackend):
    assert crowdsec_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|cidr: 192.168.0.0/16
                condition: sel
        """),
    output_format="queryonly") == "IpInRange(field, '192.168.0.0/16')"

def test_crowdsec_cidr_in_list_query(crowdsec_backend : CrowdsecBackend):
    assert crowdsec_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|cidr: 
                        - 192.168.0.0/16
                        - 10.0.0.0/8
                condition: sel
        """),
    output_format="queryonly") == "IpInRange(field, '192.168.0.0/16') || IpInRange(field, '10.0.0.0/8')"

# (TBD) Skip on purpose, doesn't seem relevant for us. Our data is always in Maps, so evt.Meta['foo bar'] works
# def test_crowdsec_field_name_with_whitespace(crowdsec_backend : CrowdsecBackend):
#     assert crowdsec_backend.convert(
#         SigmaCollection.from_yaml("""
#             title: Test
#             status: test
#             logsource:
#                 category: test_category
#                 product: test_product
#             detection:
#                 sel:
#                     field name: value
#                 condition: sel
#         """),
#     output_format="queryonly") == ""


# Stolen from splunk tests
def test_crowdsec_regex_query_implicit_or(crowdsec_backend : CrowdsecBackend):
    assert (
        crowdsec_backend.convert(
            SigmaCollection.from_yaml(
                """
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel:
                        fieldA|re:
                            - foo.*bar
                            - boo.*foo
                        fieldB: foo
                        fieldC: bar
                    condition: sel
            """
            ),
            output_format="queryonly"
        )
        == "(fieldA matches 'foo.*bar' || fieldA matches 'boo.*foo') && fieldB == 'foo' && fieldC == 'bar'"
    )


def test_crowdsec_regex_query_explicit_or(crowdsec_backend : CrowdsecBackend):
    assert (
        crowdsec_backend.convert(
            SigmaCollection.from_yaml(
                """
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel1:
                        fieldA|re: foo.*bar
                    sel2:
                        fieldB|re: boo.*foo
                    condition: sel1 or sel2
            """
            ),
            output_format="queryonly"
        )
        == "fieldA matches 'foo.*bar' || fieldB matches 'boo.*foo'"
    )




# # TODO: implement tests for all backend features that don't belong to the base class defaults, e.g. features that were
# # implemented with custom code, deferred expressions etc.



# def test_crowdsec_format1_output(crowdsec_backend : CrowdsecBackend):
#     """Test for output format format1."""
#     # TODO: implement a test for the output format
#     pass

# def test_crowdsec_format2_output(crowdsec_backend : CrowdsecBackend):
#     """Test for output format format2."""
#     # TODO: implement a test for the output format
#     pass


