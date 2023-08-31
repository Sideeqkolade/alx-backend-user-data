#!/usr/bin/env python3
"""A module for filtering logs"""
import re
from typing import List


# Construct the regex pattern to match the fields separated by the separator
patterns = {
    'extract': lambda x, y: r'(?P<field>{})=[^{}]*'.format('|'.join(x), y),
    'replace': lambda x: r'\g<field>={}'.format(x),
}

PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def filter_datum(
        fields: List[str], redaction: str, message: str, separator: str
        ) -> str:
    """Filters a log line"""
    # save the patterns into variables
    extract, replace = (patterns["extract"], patterns["replace"])

    # Use re.sub to replace the matched pattern
    return re.sub(extract(fields, separator), replace(redaction), message)
