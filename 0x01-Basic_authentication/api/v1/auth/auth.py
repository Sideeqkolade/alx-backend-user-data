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

        # check if path is in the list of excluded_paths
        if path in excluded_paths:
            return False

        normal_path = path.rstrip('/')  # remove a trailing slash if it exists
        normal_exclude_paths = [p.rstrip('/') for p in excluded_paths]

        # Check if normal_path is in normal_exclude_paths
        if normal_path in normal_exclude_paths:
            return False

        return True

    def authorization_header(self, request=None) -> str:
        """
        """
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """
        """
        return None
