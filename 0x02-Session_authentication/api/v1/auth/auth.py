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
        if not path:
            return True
        if not excluded_paths or excluded_paths == []:
            return True
        if path in excluded_paths:
            return False
        normalized_path = path.rstrip('/')  # Remove trailing slashes
        for paths in excluded_paths:
            # Remove trailing slashes
            normalized_excluded_path = paths.rstrip('/')
            if normalized_path == normalized_excluded_path:
                return False
        return True

    def authorization_header(self, request=None) -> str:
        """ Gets the authorization header field from the request
        """
        if request is not None:
            return request.headers.get('Authorization', None)
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """ Gets the current user from the request.
        """
        return None
