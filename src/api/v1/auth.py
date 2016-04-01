"""
Copyright 2016 ElasticBox All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import json
import logging
import random
import string
import urlparse
from datetime import datetime, timedelta

import jwt
from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.authn_request import OneLogin_Saml2_Authn_Request
from passlib.hash import sha512_crypt
from tornado.auth import GoogleOAuth2Mixin
from tornado.gen import coroutine, Return
from tornado.web import RequestHandler, HTTPError

from api.v1 import ELASTICKUBE_TOKEN_HEADER, ELASTICKUBE_VALIDATION_TOKEN_HEADER
from data.query import Query


def _generate_hashed_password(password):
    salt = "".join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(64))
    return {'hash': sha512_crypt.encrypt((password + salt).encode("utf-8"), rounds=40000), 'salt': salt}


def _fill_signup_invitation_request(document, firstname, lastname, password=None):
    document["firstname"] = firstname
    document["lastname"] = lastname
    document["email_validated_at"] = datetime.utcnow()
    if password is not None:
        document["password"] = _generate_hashed_password(password)


class AuthHandler(RequestHandler):

    @coroutine
    def authenticate_user(self, user, data=None):
        logging.info("Authenticating user '%(username)s'", user)

        token = dict(
            id=str(user["_id"]),
            username=user["username"],
            firstname=user["firstname"],
            lastname=user["lastname"],
            email=user["email"],
            role=user["role"],
            created=datetime.utcnow().isoformat(),
            expires=(datetime.utcnow() + timedelta(30)).isoformat()
        )

        if data is not None:
            token["data"] = data

        user["last_login"] = datetime.utcnow()
        yield self.settings["database"].Users.update({"_id": user["_id"]}, user)

        token = jwt.encode(token, self.settings["secret"], algorithm="HS256")
        self.set_cookie(ELASTICKUBE_TOKEN_HEADER, token)

        logging.info("User '%(username)s' authenticated.", user)
        raise Return(token)


class AuthProvidersHandler(RequestHandler):

    @coroutine
    def get(self):
        providers = dict()

        # If there are no users created then we need to return an empty list of providers to enable the signup flow
        if (yield Query(self.settings["database"], "Users").find_one()) is None:
            self.write({})
        else:
            settings = yield Query(self.settings["database"], "Settings").find_one()

            if "google_oauth" in settings["authentication"]:
                providers['google'] = dict(auth_url="/api/v1/auth/google")

            if "saml" in settings["authentication"]:
                providers['saml'] = dict(auth_url="/api/v1/auth/saml")

            if "password" in settings["authentication"]:
                providers['password'] = dict(regex=settings["authentication"]["password"]["regex"])

            validation_token = self.request.headers.get(ELASTICKUBE_VALIDATION_TOKEN_HEADER)
            if validation_token is not None:
                user = yield Query(self.settings["database"], "Users").find_one({"invite_token": validation_token})
                if user is not None and 'email_validated_at' not in user:
                    providers['email'] = user[u'email']

            self.write(providers)


class SignupHandler(AuthHandler):

    @staticmethod
    def _validate_signup_data(data):
        if "email" not in data:
            raise HTTPError(400, message="Email is required.")

        if "password" not in data:
            raise HTTPError(400, message="Password is required.")

        if "firstname" not in data:
            raise HTTPError(400, message="First name is required.")

        if "lastname" not in data:
            raise HTTPError(400, message="Last name is required.")

        return True

    @coroutine
    def _update_invited_user(self, validation_token, data):
        user = yield Query(self.settings["database"], "Users").find_one(
            {"invite_token": validation_token, "email": data["email"]})

        if user is not None and "email_validated_at" not in user:
            for namespace_name in user["namespaces"]:
                namespace = yield Query(self.settings["database"], "Namespaces").find_one({"name": namespace_name})
                if namespace is None:
                    logging.warn("Cannot find namespace %s", namespace_name)
                else:
                    if "members" in namespace:
                        namespace["members"].append(user["username"])
                    else:
                        namespace["members"] = [user["username"]]

                    yield Query(self.settings["database"], "Namespaces").update(namespace)

            del user["namespaces"]

            _fill_signup_invitation_request(
                user, firstname=data["firstname"], lastname=data["lastname"],
                password=data["password"])

            raise Return(user)
        else:
            raise HTTPError(403, message="Invitation not found.")

    @coroutine
    def post(self):
        try:
            data = json.loads(self.request.body)
        except Exception:
            raise HTTPError(400, message='Invalid JSON')

        validation_token = self.request.headers.get(ELASTICKUBE_VALIDATION_TOKEN_HEADER)
        if validation_token is not None:
            self._validate_signup_data(data)
            user = yield self._update_invited_user(validation_token, data)
            token = yield self.authenticate_user(user)
            self.write(token)
            self.flush()

        # Signup can be used only the first time
        elif (yield Query(self.settings["database"], "Users").find_one()) is not None:
            raise HTTPError(403, message="Onboarding already completed.")

        else:
            self._validate_signup_data(data)

            user = dict(
                email=data["email"],
                username=data["email"],
                password=_generate_hashed_password(data["password"]),
                firstname=data["firstname"],
                lastname=data["lastname"],
                role="administrator",
                schema="http://elasticbox.net/schemas/user",
                email_validated_at=datetime.utcnow().isoformat()
            )

            signup_user = yield Query(self.settings["database"], "Users").insert(user)
            token = yield self.authenticate_user(signup_user)
            self.write(token)
            self.flush()


class PasswordHandler(AuthHandler):

    @coroutine
    def post(self):
        logging.info("Initiating PasswordHandler post")

        data = json.loads(self.request.body)
        if "username" not in data:
            raise HTTPError(400, reason="Missing username in body request.")

        if "password" not in data:
            raise HTTPError(400, reason="Missing password in body request.")

        username = data["username"]
        password = data["password"]

        user = yield self.settings["database"].Users.find_one({"username": username})
        if not user:
            logging.debug("Username '%s' not found.", username)
            raise HTTPError(401, reason="Invalid username or password.")

        encoded_user_password = user["password"]["hash"].encode("utf-8")
        if sha512_crypt.verify((password + user["password"]["salt"]).encode("utf-8"), encoded_user_password):
            token = yield self.authenticate_user(user)
            self.write(token)
            self.flush()
        else:
            logging.info("Invalid password for user '%s'.", username)
            raise HTTPError(401, reason="Invalid username or password.")


class GoogleOAuth2LoginHandler(AuthHandler, GoogleOAuth2Mixin):

    @coroutine
    def get(self):
        logging.info("Initiating Google OAuth.")

        settings = yield Query(self.settings["database"], "Settings").find_one()
        google_oauth = settings[u'authentication'].get('google_oauth', None)
        if google_oauth is None:
            raise HTTPError(403, 'Forbidden request')

        # Add OAuth settings for GoogleOAuth2Mixin
        self.settings['google_oauth'] = {
            'key': google_oauth['key'],
            'secret': google_oauth['secret']
        }

        code = self.get_argument('code', False)
        if code:
            logging.debug("Google redirect received.")

            auth_data = yield self.get_authenticated_user(
                redirect_uri=google_oauth["redirect_uri"],
                code=code)

            auth_user = yield self.oauth2_request(
                "https://www.googleapis.com/oauth2/v1/userinfo",
                access_token=auth_data['access_token'])

            if auth_user["verified_email"]:
                user = yield self.settings["database"].Users.find_one({"email": auth_user["email"]})

                # Validate user if it signup by OAuth2
                if user and 'email_validated_at' not in user:
                    logging.debug('User validated via OAuth2 %s', auth_user["email"])
                    _fill_signup_invitation_request(
                        user, firstname=auth_data.get('given_name', auth_data.get('name', "")),
                        lastname=auth_data.get('family_name', ""), password=None)

                    user = yield Query(self.settings["database"], 'Users').update(user)

                if user:
                    yield self.authenticate_user(user)
                    self.redirect('/')
                else:
                    logging.debug("User '%s' not found", auth_user["email"])
                    raise HTTPError(400, "Invalid authentication request.")
            else:
                logging.info("User email '%s' not verified.", auth_user["email"])
                raise HTTPError(400, "Email is not verified.")
        else:
            logging.debug("Redirecting to google for authentication.")
            yield self.authorize_redirect(
                redirect_uri=google_oauth['redirect_uri'],
                client_id=google_oauth['key'],
                scope=['profile', 'email'],
                response_type='code',
                extra_params={'approval_prompt': 'auto'})


class Saml2LoginHandler(AuthHandler):

    def _get_saml_settings(self, saml_config, settings):
        saml_settings = dict(
            sp=dict(
                entityId=settings["hostname"],
                assertionConsumerService=dict(
                    url="{0}/api/v1/auth/saml".format(settings["hostname"]),
                    binding=OneLogin_Saml2_Constants.BINDING_HTTP_POST),
                singleLogoutService=dict(
                    url="{0}/login".format(settings["hostname"]),
                    binding=OneLogin_Saml2_Constants.BINDING_HTTP_REDIRECT),
                NameIDFormat=OneLogin_Saml2_Constants.NAMEID_TRANSIENT,
                x509cert=saml_config.get("sp_certificate", ""),
                privateKey=saml_config.get("sp_key", "")
            ),
            idp=dict(
                entityId=saml_config["metadata_uri"],
                singleSignOnService=dict(
                    url=saml_config["sign_on_uri"],
                    binding=OneLogin_Saml2_Constants.BINDING_HTTP_REDIRECT),
                singleLogoutService=dict(
                    url=saml_config["sign_out_uri"],
                    binding=OneLogin_Saml2_Constants.BINDING_HTTP_REDIRECT),
                x509cert=saml_config["idp_certificate"]
            )
        )

        if len(saml_settings['sp']['x509cert']) > 0 and len(saml_settings['sp']['privateKey']) > 0:
            saml_settings['security'] = dict(
                authnRequestsSigned=True,
                signMetadata=True,
                wantMessagesSigned=True,
                wantAssertionsSigned=True
            )

        return saml_settings

    @coroutine
    def _get_saml_auth(self, request):
        settings = yield Query(self.settings["database"], "Settings").find_one()
        saml_config = settings[u'authentication'].get('saml', None)
        if saml_config is None:
            raise HTTPError(403, 'Forbidden request')

        netloc = urlparse.urlparse(settings["hostname"]).netloc
        host, _, port = netloc.partition(':')
        saml_request = dict(
            http_host=host,
            script_name=request.path,
            get_data={k: v[0] if len(v) == 1 else v for k, v in request.query_arguments.items()},
            post_data={k: v[0] if len(v) == 1 else v for k, v in request.body_arguments.items()}
        )

        if port:
            saml_request['server_port'] = port

        saml_settings = self._get_saml_settings(saml_config, settings)

        raise Return(OneLogin_Saml2_Auth(saml_request, saml_settings))

    @coroutine
    def get(self):
        logging.info("Initiating SAML 2.0 Auth.")
        auth = yield self._get_saml_auth(self.request)

        if self.get_query_arguments('slo', False):
            encoded_token = self.request.headers.get(ELASTICKUBE_TOKEN_HEADER)
            if encoded_token is None:
                encoded_token = self.get_cookie(ELASTICKUBE_TOKEN_HEADER)

            if encoded_token is None:
                self.redirect('/')
            else:
                token = None
                try:
                    token = jwt.decode(encoded_token, self.settings['secret'], algorithm='HS256')
                except jwt.DecodeError as jwt_error:
                    logging.exception(jwt_error)
                    self.write_message({"error": {"message": "Invalid token."}})
                    self.close(httplib.UNAUTHORIZED, "Invalid token.")

                if token:
                    logging.debug("Redirecting to SAML for logout.")
                    self.redirect(auth.logout(name_id=token["data"]["name_id"], session_index=token["data"]["session_index"]))

        else:
            logging.debug("Redirecting to SAML for authentication.")
            self.redirect(auth.login())

    @coroutine
    def post(self):
        logging.info("SAML redirect received.")

        auth = yield self._get_saml_auth(self.request)
        auth.process_response()

        errors = auth.get_errors()
        if len(errors) > 0:
            logging.info("SAML authentication error: '%s'.", auth.get_last_error_reason())
            raise HTTPError(401, reason=auth.get_last_error_reason())

        if not auth.is_authenticated():
            logging.info("SAML user not authenticated.")
            raise HTTPError(401, reason="SAML user not authenticated.")

        user_attributes = auth.get_attributes()
        logging.debug('SAML Attributes received: {0}'.format(user_attributes))
        settings = yield Query(self.settings["database"], "Settings").find_one()
        saml = settings[u'authentication'].get('saml', None)

        if saml["email_mapping"] not in user_attributes:
            logging.info('User Email attribute (%s) missing at response.', saml["email_mapping"])
            raise HTTPError(401, reason='User Email attribute not found. Please review mapping at SAML settings')

        user_email = user_attributes.get(saml["email_mapping"], [""])[0]
        user = yield self.settings["database"].Users.find_one({"email": user_email})

        # Validate user if it signup by SAML
        if user and 'email_validated_at' not in user:
            logging.debug('User validated via SAML %s', user_email)
            _fill_signup_invitation_request(
                user,
                firstname=user_attributes.get(saml["first_name_mapping"], [""])[0],
                lastname=user_attributes.get(saml["last_name_mapping"], [""])[0],
                password=None)

            user = yield Query(self.settings["database"], 'Users').update(user)

        if user:
            data = dict(name_id=auth.get_nameid(), session_index=auth.get_session_index())
            yield self.authenticate_user(user, data)
            self.redirect('/')
        else:
            logging.debug("User '%s' not found", user_email)
            raise HTTPError(400, "Invalid authentication request.")
