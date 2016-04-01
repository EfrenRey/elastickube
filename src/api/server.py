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

import sys
import logging

from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from tornado.netutil import bind_unix_socket
from tornado.web import Application

from api.v1 import configure, initialize
from api.v1.main import MainWebSocketHandler
from api.v1.auth import AuthProvidersHandler, GoogleOAuth2LoginHandler, PasswordHandler, Saml2LoginHandler, SignupHandler
from api.v1.icons import IconGenerator

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)


def setup_server():
    # Config tornado.curl_httpclient to use NullHandler
    tornado_logger = logging.getLogger('tornado.curl_httpclient')
    tornado_logger.addHandler(logging.NullHandler())
    tornado_logger.propagate = False

    settings = dict(
        autoreload=True,
        secret="ElasticKube",
    )

    configure(settings)
    IOLoop.current().add_future(initialize(settings), start_server)


def start_server(future):
    settings = future.result()

    handlers = [
        (r"/api/v1/auth/providers", AuthProvidersHandler),
        (r"/api/v1/auth/signup", SignupHandler),
        (r"/api/v1/auth/login", PasswordHandler),
        (r"/api/v1/auth/google", GoogleOAuth2LoginHandler),
        (r"/api/v1/auth/saml", Saml2LoginHandler),
        (r"/api/v1/ws", MainWebSocketHandler),
        (r"/icons/(?P<entity_id>[^\/]+)\/(?P<chart_id>[^\/]+)", IconGenerator)
    ]

    application = Application(handlers, **settings)

    server = HTTPServer(application)
    socket = bind_unix_socket("/var/run/elastickube-api.sock", mode=0777)
    server.add_socket(socket)


if __name__ == "__main__":
    setup_server()
    IOLoop.current().start()
