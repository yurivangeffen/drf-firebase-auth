# -*- coding: utf-8 -*-
"""
Authentication backend for handling firebase user.idToken from incoming
Authorization header, verifying, and locally authenticating
Author: Gary Burgmann
Email: garyburgmann@gmail.com
Location: Springfield QLD, Australia
Last update: 2020-04-13 (Yuri van Geffen)
"""
import json
import uuid

import firebase_admin
from firebase_admin import auth as firebase_auth
from firebase_admin import exceptions as firebase_exceptions
from django.utils.encoding import smart_text
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from rest_framework import (
    authentication,
    exceptions
)

from drf_firebase_auth.settings import api_settings
from drf_firebase_auth.models import (
    FirebaseUser,
    FirebaseUserProvider
)

User = get_user_model()

firebase_credentials = firebase_admin.credentials.Certificate(
    api_settings.FIREBASE_SERVICE_ACCOUNT_KEY
)
firebase = firebase_admin.initialize_app(firebase_credentials)


class BaseFirebaseAuthentication(authentication.BaseAuthentication):
    """
    Token based authentication using firebase.
    """
    def authenticate(self, request):
        """
        With ALLOW_ANONYMOUS_REQUESTS, set request.user to an AnonymousUser,
        allowing us to configure access at the permissions level.
        """
        authorization_header = authentication.get_authorization_header(request)
        if api_settings.ALLOW_ANONYMOUS_REQUESTS and not authorization_header:
            return (AnonymousUser(), None)

        """
        Returns a tuple of len(2) of `User` and the decoded firebase token if
        a valid signature has been supplied using Firebase authentication.
        """
        firebase_token = self.get_token(request)

        decoded_token = self.decode_token(firebase_token)

        firebase_user = self.authenticate_token(decoded_token)

        return (firebase_user, decoded_token)

    def get_token(self, request):
        raise NotImplementedError('get_token() has not been implemented.')

    def decode_token(self, firebase_token):
        raise NotImplementedError('decode_token() has not been implemented.')

    def authenticate_token(self, decoded_token):
        raise NotImplementedError('authenticate_token() has not been implemented.')

class FirebaseAuthentication(BaseFirebaseAuthentication):
    """
    Clients should authenticate by passing the token key in the
    'Authorization' HTTP header, prepended with the string specified in the
    settings.FIREBASE_AUTH_HEADER_PREFIX setting (Default = 'JWT')
    """
    www_authenticate_realm = 'api'

    def get_token(self, request):
        """
        Parse Authorization header and retrieve JWT
        """
        authorization_header = \
            authentication.get_authorization_header(request).split()
        auth_header_prefix = api_settings.FIREBASE_AUTH_HEADER_PREFIX.lower()

        if not authorization_header or len(authorization_header) != 2:
            raise exceptions.AuthenticationFailed(
                'Invalid Authorization header format, expecting: JWT <token>.'
            )

        if smart_text(authorization_header[0].lower()) != auth_header_prefix:
            raise exceptions.AuthenticationFailed(
                'Invalid Authorization header prefix, expecting: JWT.'
            )

        return authorization_header[1]

    def decode_token(self, firebase_token):
        """
        Attempt to verify JWT from Authorization header with Firebase and
        return the decoded token
        """
        try:
            return firebase_auth.verify_id_token(
                firebase_token,
                check_revoked=api_settings.FIREBASE_CHECK_JWT_REVOKED
            )
        except firebase_auth.RevokedIdTokenError:
            raise exceptions.AuthenticationFailed(
                'Token revoked, inform the user to reauthenticate or '
                'signOut().'
            )
        except firebase_auth.ExpiredIdTokenError:
            raise exceptions.AuthenticationFailed(
                'Token expired, inform the user to refresh their token or '
                'sign out and in again.'
            )
        except firebase_auth.InvalidIdTokenError:
            raise exceptions.AuthenticationFailed(
                'JWT was found to be invalid, or the App’s project ID cannot '
                'be determined.'
            )

    def authenticate_token(self, decoded_token):
        """
        Returns firebase user if token is authenticated
        """
        try:
            uid = decoded_token.get('uid')
            firebase_user = firebase_auth.get_user(uid)
            if api_settings.FIREBASE_AUTH_EMAIL_VERIFICATION:
                if not firebase_user.email_verified:
                    raise exceptions.AuthenticationFailed(
                        'Email address of this user has not been verified.'
                    )
            firebase_user.is_staff = firebase_user.custom_claims['admin']
            firebase_user.is_authenticated = True
            return firebase_user
        except ValueError:
            raise exceptions.AuthenticationFailed(
                'User ID is None, empty or malformed'
            )
        except firebase_exceptions.FirebaseError:
            raise exceptions.AuthenticationFailed(
                'Error retrieving the user, or the specified user ID does not '
                'exist'
            )
            
    def authenticate_header(self, request):
        """
        Return a string to be used as the value of the `WWW-Authenticate`
        header in a `401 Unauthenticated` response, or `None` if the
        authentication scheme should return `403 Permission Denied` responses.
        """
        auth_header_prefix = api_settings.FIREBASE_AUTH_HEADER_PREFIX.lower()
        return '{0} realm="{1}"'.format(auth_header_prefix, self.www_authenticate_realm)
