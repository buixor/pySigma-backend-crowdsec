import pytest
from sigma.collection import SigmaCollection
from sigma.backends.crowdsec import crowdsecBackend

@pytest.fixture
def crowdsec_backend():
    return crowdsecBackend()

# TODO: implement tests for some basic queries and their expected results.
def test_crowdsec_and_expression(crowdsec_backend : crowdsecBackend):
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
        """)
    ) == ['<insert expected result here>']

def test_crowdsec_or_expression(crowdsec_backend : crowdsecBackend):
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
        """)
    ) == ['<insert expected result here>']

def test_crowdsec_and_or_expression(crowdsec_backend : crowdsecBackend):
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
        """)
    ) == ['<insert expected result here>']

def test_crowdsec_or_and_expression(crowdsec_backend : crowdsecBackend):
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
        """)
    ) == ['<insert expected result here>']

def test_crowdsec_in_expression(crowdsec_backend : crowdsecBackend):
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
        """)
    ) == ['<insert expected result here>']

def test_crowdsec_regex_query(crowdsec_backend : crowdsecBackend):
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
        """)
    ) == ['<insert expected result here>']

def test_crowdsec_cidr_query(crowdsec_backend : crowdsecBackend):
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
        """)
    ) == ['<insert expected result here>']

def test_crowdsec_field_name_with_whitespace(crowdsec_backend : crowdsecBackend):
    assert crowdsec_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field name: value
                condition: sel
        """)
    ) == ['<insert expected result here>']

# TODO: implement tests for all backend features that don't belong to the base class defaults, e.g. features that were
# implemented with custom code, deferred expressions etc.



def test_crowdsec_format1_output(crowdsec_backend : crowdsecBackend):
    """Test for output format format1."""
    # TODO: implement a test for the output format
    pass

def test_crowdsec_format2_output(crowdsec_backend : crowdsecBackend):
    """Test for output format format2."""
    # TODO: implement a test for the output format
    pass


