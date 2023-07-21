from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule
from sigma.conversion.base import TextQueryBackend
from sigma.conditions import ConditionItem, ConditionAND, ConditionOR, ConditionNOT
from sigma.conversion.deferred import DeferredQueryExpression
from sigma.types import SigmaCompareExpression, SigmaRegularExpression
from typing import Pattern, Union, ClassVar, Optional, Tuple, List, Dict, Any
from sigma.processing.pipeline import ProcessingPipeline
from sigma.pipelines.crowdsec import crowdsec_pipeline # TODO: add pipeline imports or delete this line
import sigma
import os
import re
from typing import ClassVar, Dict, Tuple, Pattern, List, Any

class crowdsecBackend(TextQueryBackend):
    """crowdsec backend."""
    backend_processing_pipeline : ClassVar[ProcessingPipeline] = crowdsec_pipeline()
    # TODO: change the token definitions according to the syntax. Delete these not supported by your backend.
    # See the pySigma documentation for further infromation:
    # https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html

    # Operator precedence: tuple of Condition{AND,OR,NOT} in order of precedence.
    # The backend generates grouping if required
    name : ClassVar[str] = "crowdsec backend"
    formats : Dict[str, str] = {
        "default": "Plain crowdsec queries",
        "default_yaml": "default crowdsec scenario format",
    }
    requires_pipeline : bool = True            # TODO: does the backend requires that a processing pipeline is provided? This information can be used by user interface programs like Sigma CLI to warn users about inappropriate usage of the backend.

    precedence : ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (ConditionNOT, ConditionAND, ConditionOR)
    group_expression : ClassVar[str] = "({expr})"   # Expression for precedence override grouping as format string with {expr} placeholder
    parenthesize : bool = True     # Reflect parse tree by putting parenthesis around all expressions - use this for target systems without strict precedence rules.

    # Generated query tokens
    token_separator : str = " "     # separator inserted between all boolean operators
    or_token : ClassVar[str] = "||"
    and_token : ClassVar[str] = "&&"
    not_token : ClassVar[str] = "not"
    eq_token : ClassVar[str] = " == " #custom
    # String output
    ## Fields
    ### Quoting
    field_quote : ClassVar[str] = "'"                               # Character used to quote field characters if field_quote_pattern matches (or not, depending on field_quote_pattern_negation). No field name quoting is done if not set.
    field_quote_pattern : ClassVar[Pattern] = re.compile("^[a-zA-Z]") #custom  # Quote field names if this pattern (doesn't) matches, depending on field_quote_pattern_negation. Field name is always quoted if pattern is not set.
    field_quote_pattern_negation : ClassVar[bool] = True            # Negate field_quote_pattern result. Field name is quoted if pattern doesn't matches if set to True (default).

    ### Escaping
    field_escape : ClassVar[str] = "\\"               # Character to escape particular parts defined in field_escape_pattern.
    field_escape_quote : ClassVar[bool] = True        # Escape quote string defined in field_quote
    field_escape_pattern : ClassVar[Pattern] = re.compile("\\s")   # All matches of this pattern are prepended with the string contained in field_escape.

    ## Values

    str_quote       : ClassVar[str] = '"'     # string quoting character (added as escaping character)
    escape_char     : ClassVar[str] = "\\"    # Escaping character for special characrers inside string ##TBD : sort this one out
    wildcard_multi  : ClassVar[str] = "*"     # Character used as multi-character wildcard
    wildcard_single : ClassVar[str] = "?"     # Character used as single-character wildcard
    #wildcard_multi  : ClassVar[str] = ".*"     # Character used as multi-character wildcard
    #wildcard_single : ClassVar[str] = "."     # Character used as single-character wildcard
    add_escaped     : ClassVar[str] = "\\"    # Characters quoted in addition to wildcards and string quote
    filter_chars    : ClassVar[str] = ""      # Characters filtered
    bool_values     : ClassVar[Dict[bool, str]] = {   # Values to which boolean values are mapped.
        True: "true",
        False: "false",
    }

    # String matching operators. if none is appropriate eq_token is used.
    startswith_expression : ClassVar[str] = "{field} startsWith {value}"
    endswith_expression   : ClassVar[str] = "{field} endsWith {value}"
    contains_expression   : ClassVar[str] = "{field} contains {value}"
    wildcard_match_expression : ClassVar[str] = "Match({value}, {field})"      # Special expression if wildcards can't be matched with the eq_token operator

    # Regular expressions
    # Regular expression query as format string with placeholders {field}, {regex}, {flag_x} where x
    # is one of the flags shortcuts supported by Sigma (currently i, m and s) and refers to the
    # token stored in the class variable re_flags.
    re_expression : ClassVar[str] = "{field} matches '{regex}'"
    re_escape_char : ClassVar[str] = "\\\\"               # Character used for escaping in regular expressions
    re_escape : ClassVar[Tuple[str]] = ("")               # List of strings that are escaped
    re_escape_escape_char : bool = True                 # If True, the escape character is also escaped
    re_flag_prefix : bool = True                        # If True, the flags are prepended as (?x) group at the beginning of the regular expression, e.g. (?i). If this is not supported by the target, it should be set to False.
    # Mapping from SigmaRegularExpressionFlag values to static string templates that are used in
    # flag_x placeholders in re_expression template.
    # By default, i, m and s are defined. If a flag is not supported by the target query language,
    # remove it from re_flags or don't define it to ensure proper error handling in case of appearance.
    # re_flags : Dict[SigmaRegularExpressionFlag, str] = {
    #     SigmaRegularExpressionFlag.IGNORECASE: "i",
    #     SigmaRegularExpressionFlag.MULTILINE : "m",
    #     SigmaRegularExpressionFlag.DOTALL    : "s",
    # }

    # cidr expressions
    cidr_wildcard : ClassVar[str] = "*"    # Character used as single wildcard
    cidr_expression : ClassVar[str] = "IpInRange({field}, '{value}')"    # CIDR expression query as format string with placeholders {field} = {value}
    cidr_in_list_expression : ClassVar[str] = "{field} in ({value})"    # CIDR expression query as format string with placeholders {field} = in({list})

    # Numeric comparison operators
    compare_op_expression : ClassVar[str] = "{field}{operator}'{value}'"  # Compare operation query as format string with placeholders {field}, {operator} and {value}
    # Mapping between CompareOperators elements and strings used as replacement for {operator} in compare_op_expression
    compare_operators : ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT  : "<",
        SigmaCompareExpression.CompareOperators.LTE : "<=",
        SigmaCompareExpression.CompareOperators.GT  : ">",
        SigmaCompareExpression.CompareOperators.GTE : ">=",
    }

    # Null/None expressions
    field_null_expression : ClassVar[str] = "{field} == ''"          # Expression for field has null value as format string with {field} placeholder for field name

    # Field existence condition expressions.
    field_exists_expression : ClassVar[str] = "exists({field})"             # Expression for field existence as format string with {field} placeholder for field name
    field_not_exists_expression : ClassVar[str] = "notexists({field})"      # Expression for field non-existence as format string with {field} placeholder for field name. If not set, field_exists_expression is negated with boolean NOT.

    # Field value in list, e.g. "field in (value list)" or "field containsall (value list)"
    convert_or_as_in : ClassVar[bool] = False                     # Convert OR as in-expression
    convert_and_as_in : ClassVar[bool] = False                    # Convert AND as in-expression
    in_expressions_allow_wildcards : ClassVar[bool] = True       # Values in list can contain wildcards. If set to False (default) only plain values are converted into in-expressions.
    field_in_list_expression : ClassVar[str] = "{field} {op} [{list}]"  # Expression for field in list of values as format string with placeholders {field}, {op} and {list}
    or_in_operator : ClassVar[str] = "in"               # Operator used to convert OR into in-expressions. Must be set if convert_or_as_in is set
    #this one can be tricky
    #and_in_operator : ClassVar[str] = "contains-all"    # Operator used to convert AND into in-expressions. Must be set if convert_and_as_in is set
    list_separator : ClassVar[str] = ", "               # List element separator

    # Value not bound to a field
    unbound_value_str_expression : ClassVar[str] = 'evt.Line.Raw contains {value}'   # Expression for string value not bound to a field as format string with placeholder {value}
    unbound_value_num_expression : ClassVar[str] = '{value}'     # Expression for number value not bound to a field as format string with placeholder {value}
    unbound_value_re_expression : ClassVar[str] = 'evt.Line.Raw matches "{value}"'   # Expression for regular expression not bound to a field as format string with placeholder {value} and {flag_x} as described for re_expression

    # Query finalization: appending and concatenating deferred query part
    deferred_start : ClassVar[str] = "\n| "               # String used as separator between main query and deferred parts
    deferred_separator : ClassVar[str] = "\n| "           # String used to join multiple deferred query parts
    deferred_only_query : ClassVar[str] = ""            # String used as query if final query only contains deferred expression

    # TODO: implement custom methods for query elements not covered by the default backend base.
    # Documentation: https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html

    def convert_condition_not(self, cond : ConditionNOT, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of NOT conditions."""
        arg = cond.args[0]

        try:
            if arg.__class__ in self.precedence:        # group if AND or OR condition is negated
                #print("#1 : " + self.convert_condition(arg, state))
                return self.not_token + self.token_separator + self.convert_condition_group(arg, state) 
            else:
                #print("#2 : " + self.convert_condition(arg, state))
                expr = self.convert_condition(arg, state)
                if isinstance(expr, DeferredQueryExpression):      # negate deferred expression and pass it to parent
                    return expr.negate()
                else:                                             # convert negated expression to string
                    return self.not_token + self.token_separator + "("  + expr + ")"
        except TypeError:       # pragma: no cover
            raise NotImplementedError("Operator 'not' not supported by the backend")

    def finalize_query_default_yaml(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> Any:
        # TODO: implement the per-query output for the output format format1 here. Usually, the generated query is
        # embedded into a template, e.g. a JSON format with additional information from the Sigma rule.
        # TODO: proper type annotation.

        prefilter = ""
        if rule.logsource.category == "webserver":
            prefilter = "evt.Meta.service == 'http'"
        if rule.logsource.category == "process_creation" and rule.logsource.product == "windows":
            prefilter = "(evt.Meta.service == 'sysmon' && evt.Parsed.EventID == '1')"
        formatted_desc = rule.description.replace("\n", "\n  ")

        #we generate the rule name based on the rule path
        if rule.source.path == "":
            raise ValueError("Rule path is empty")
        else:
            name = "sigma/"+os.path.basename(rule.source.path).split(".")[0]

        ret = f"""type: trigger
name: {name}
description: |
  {formatted_desc}
filter: |
  {prefilter} && ({query})
blackhole: 2m
labels:
  type: exploit
  remediation: true"""

        return ret

    def finalize_output_default_yaml(self, queries: List[str]) -> Any:
        # TODO: implement the output finalization for all generated queries for the format format1 here. Usually,
        # the single generated queries are embedded into a structure, e.g. some JSON or XML that can be imported into
        # the SIEM.
        # TODO: proper type annotation. Sigma CLI supports:
        # - str: output as is.
        # - bytes: output in file only (e.g. if a zip package is output).
        # - dict: output serialized as JSON.
        # - list of str: output each item as is separated by two newlines.
        # - list of dict: serialize each item as JSON and output all separated by newlines.
        return "\n---".join(queries)
    
    def finalize_query_format2(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> Any:
        # TODO: implement the per-query output for the output format format2 here. Usually, the generated query is
        # embedded into a template, e.g. a JSON format with additional information from the Sigma rule.
        # TODO: proper type annotation.
        return query

    def finalize_output_format2(self, queries: List[str]) -> Any:
        # TODO: implement the output finalization for all generated queries for the format format2 here. Usually,
        # the single generated queries are embedded into a structure, e.g. some JSON or XML that can be imported into
        # the SIEM.
        # TODO: proper type annotation. Sigma CLI supports:
        # - str: output as is.
        # - bytes: output in file only (e.g. if a zip package is output).
        # - dict: output serialized as JSON.
        # - list of str: output each item as is separated by two newlines.
        # - list of dict: serialize each item as JSON and output all separated by newlines.
        return "\n".join(queries)
    
    