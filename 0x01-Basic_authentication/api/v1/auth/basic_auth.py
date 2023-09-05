#!/usr/bin/env python3
"""Basic authentication module for the API."""
from .auth import Auth
import base64
# from models.user import User


class BasicAuth(Auth):
    """BAsic Authentication Class"""
    def extract_base64_authorization_header(
            self, authorization_header: str
            ) -> str:
        """ Extracts the Base64 part of the Authorization header
            for a Basic Authentication.
        """
        if authorization_header is not None and isinstance(
                authorization_header, str):
            if authorization_header.startswith("Basic "):
                split_string = authorization_header.split(" ")
                if len(split_string) == 2:
                    return split_string[1]
            return None

    def decode_base64_authorization_header(
            self, base64_authorization_header: str
            ) -> str:
        """ Decodes a base64-encoded authorization header.
        """
        if base64_authorization_header is not None and isinstance(
                base64_authorization_header, str):
            try:
                decoded_data = base64.b64decode(base64_authorization_header)
                return decoded_data.decode('utf-8')
            except (base64.binascii.Error, UnicodeDecodeError):
                return None
