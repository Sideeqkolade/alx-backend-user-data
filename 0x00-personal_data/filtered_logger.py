#!/usr/bin/env python3
"""A module for filtering logs"""
import re
import os
import mysql.connector
import logging
from typing import List, Tuple


# Construct the regex pattern to match the fields separated by the separator
patterns = {
    'extract': lambda x, y: r'(?P<field>{})=[^{}]*'.format('|'.join(x), y),
    'replace': lambda x: r'\g<field>={}'.format(x),
}

PII_FIELDS: Tuple = ("name", "email", "phone", "ssn", "password")

USERNAME: str = os.getenv("PERSONAL_DATA_DB_USERNAME")
PASSWORD: str = os.getenv("PERSONAL_DATA_DB_PASSWORD")
HOST: str = os.getenv("PERSONAL_DATA_DB_HOST")
DATABASE: str = os.getenv("PERSONAL_DATA_DB_NAME")


def filter_datum(
        fields: List[str], redaction: str, message: str, separator: str
        ) -> str:
    """Filters a log line"""
    # save the patterns into variables
    extract, replace = (patterns["extract"], patterns["replace"])

    # Use re.sub to replace the matched pattern
    return re.sub(extract(fields, separator), replace(redaction), message)


def get_logger() -> logging.Logger:
    """Creates a new logger for user data"""
    logger = logging.getLogger('user_data')

    # set the logging level
    logger.setLevel(logging.INFO)  # Adjust to the desr=ired level(INFO, DEBUG)

    # Create a logging handler and set the formatter
    handler = logging.StreamHandler()
    handler.setFormatter(RedactingFormatter(PII_FIELDS))

    logger.propagate = False

    # Add the handler to the logger
    logger.addHandler(handler)
    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """Creates a connector to a database """
    connection = mysql.connector.connect(
        host=HOST,
        user=USERNAME,
        password=PASSWORD,
        database=DATABASE
    )
    return connection


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class"""

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """formats a LogRecord"""
        msg = super(RedactingFormatter, self).format(record)
        txt = filter_datum(self.fields, self.REDACTION, msg, self.SEPARATOR)
        return txt
