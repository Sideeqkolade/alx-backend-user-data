#!/usr/bin/env python3
""" Module to manage API authentication
"""
from flask import request
from typing import List, TypeVar


class Auth:
    """ A class authentication"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ Checks if a path requires authentication
        """
        # check if path is None
        if path is None:
            return True

        # check if excluded_path is None or empty
        if excluded_paths is None or len(excluded_paths) == 0:
            return True

        for excluded_path in excluded_paths:
            # Remove the trailing wildcard if it exists
            if excluded_path.endswith("*"):
                excluded_path = excluded_path[:-1]

            # Check if the path starts with the excluded path
            if path.startswith(excluded_path):
                return False

        return True

    def authorization_header(self, request=None) -> str:
        """ Gets the authorization header field from the request
        """
        if request is not None:
            return request.headers.get('Authorization', None)
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """
        """
        return None
