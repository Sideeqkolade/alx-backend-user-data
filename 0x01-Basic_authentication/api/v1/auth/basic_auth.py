#!/usr/bin/env python3
"""Basic authentication module for the API."""
from .auth import Auth
import base64
from models.user import User
from typing import TypeVar


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

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str
            ) -> (str, str):
        """ Extracts user credentials from a base64-decoded authorization
            header that uses the Basic authentication flow.
        """
        if decoded_base64_authorization_header is not None and isinstance(
                decoded_base64_authorization_header, str):
            if ':' in decoded_base64_authorization_header:
                decoded_string = decoded_base64_authorization_header.split(':')
                return tuple(decoded_string)

        return None, None

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str
            ) -> TypeVar('User'):
        """ Retrieves a user based on the user's authentication credentials.
        """
        # Check if user_email and user_pwd are valid strings
        if (user_email is not None and isinstance(user_email, str)) and (
                user_pwd is not None and isinstance(user_pwd, str)):
            # Use the search method to find users by email in your database
            matching_users = User.search({'email': user_email})

            # Check if there are any matching users
            if matching_users:
                # Loop through matching users and check their passwords
                for user in matching_users:
                    # Return the user instance if the password is valid
                    if user.is_valid_password(user_pwd):
                        return user

        # If any condition is not met, return None
        return None
