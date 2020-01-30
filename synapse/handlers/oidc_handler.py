# -*- coding: utf-8 -*-
# Copyright 2019 The Matrix.org Foundation C.I.C.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import logging

import attr
from urllib.parse import urlparse
import saml2

from oic import rndstr
from oic.oic import Client
from oic.oic.message import AuthorizationResponse
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from synapse.api.errors import SynapseError
from synapse.http.servlet import parse_string
from synapse.rest.client.v1.login import SSOAuthHandler
from synapse.types import UserID, map_username_to_mxid_localpart
from synapse.util.async_helpers import Linearizer

logger = logging.getLogger(__name__)


class OIDCHandler:
    def __init__(self, hs):
        self._oidc_client = Client(
            client_id=hs.config.oidc_client_id, client_authn_method=CLIENT_AUTHN_METHOD
        )
        self._oidc_client.set_client_secret(hs.config.oidc_client_secret)
        self._oidc_client.provider_config(hs.config.oidc_discovery_url)
        self._oidc_client.redirect_uris = [
            "http://localhost:8008/_matrix/oidc/authn_response"
        ]

        # self._saml_client = Saml2Client(hs.config.saml2_sp_config)
        self._sso_auth_handler = SSOAuthHandler(hs)
        self._registration_handler = hs.get_registration_handler()

        self._clock = hs.get_clock()
        self._datastore = hs.get_datastore()
        self._hostname = hs.hostname
        # self._saml2_session_lifetime = hs.config.saml2_session_lifetime
        # self._mxid_source_attribute = hs.config.saml2_mxid_source_attribute
        # self._grandfathered_mxid_source_attribute = (
        #     hs.config.saml2_grandfathered_mxid_source_attribute
        # )
        # self._mxid_mapper = hs.config.saml2_mxid_mapper

        # # identifier for the external_ids table
        self._auth_provider_id = "oidc"

        # # a map from saml session id to Saml2SessionData object
        # self._outstanding_requests_dict = {}

        # # a lock on the mappings
        self._mapping_lock = Linearizer(name="oidc_mapping", clock=self._clock)

    def handle_redirect_request(self, client_redirect_url):
        """Handle an incoming request to /login/sso/redirect

        Args:
            client_redirect_url (bytes): the URL that we should redirect the
                client to when everything is done

        Returns:
            bytes: URL to redirect to
        """
        state = "{}.{}".format(client_redirect_url.decode("utf-8"), rndstr())
        nonce = rndstr()

        args = {
            "client_id": self._oidc_client.client_id,
            "response_type": "code",
            "scope": ["openid"],
            "nonce": nonce,
            "state": state,
            "next": client_redirect_url,
        }

        auth_req = self._oidc_client.construct_AuthorizationRequest(request_args=args)
        login_url = auth_req.request(self._oidc_client.authorization_endpoint)

        return login_url

    async def handle_oidc_response(self, request):
        """Handle an incoming request to /_matrix/oidc/authn_response

        Args:
            request (SynapseRequest): the incoming request from the browser. We'll
                respond to it with a redirect.

        Returns:
            Deferred[none]: Completes once we have handled the request.
        """
        aresp = self._oidc_client.parse_response(
            AuthorizationResponse,
            info=request.uri.decode("utf-8"),
            sformat="urlencoded",
        )

        args = {"code": aresp["code"]}

        resp = self._oidc_client.do_access_token_request(
            state=aresp["state"], request_args=args, authn_method="client_secret_basic"
        )

        userinfo = self._oidc_client.do_user_info_request(state=aresp["state"])

        user_id = await self._map_oidc_response_to_user(userinfo)
        logger.info(aresp["state"].split(".")[0])
        self._sso_auth_handler.complete_sso_login(
            user_id, request, aresp["state"].split(".")[0]
        )

    async def _map_oidc_response_to_user(self, userinfo):
        logger.info(userinfo)
        try:
            remote_user_id = userinfo["sub"]
        except KeyError:
            logger.warning("OIDC response lacks a 'sub' claim")
            raise SynapseError(400, "sub not in OIDC response")

        # try:
        #     mxid_source = saml2_auth.ava[self._mxid_source_attribute][0]
        # except KeyError:
        #     logger.warning(
        #         "SAML2 response lacks a '%s' attestation", self._mxid_source_attribute
        #     )
        #     raise SynapseError(
        #         400, "%s not in SAML2 response" % (self._mxid_source_attribute,)
        #     )

        # self._outstanding_requests_dict.pop(saml2_auth.in_response_to, None)

        displayName = userinfo["preferred_username"]

        with (await self._mapping_lock.queue(self._auth_provider_id)):
            # first of all, check if we already have a mapping for this user
            logger.info(
                "Looking for existing mapping for user %s:%s",
                self._auth_provider_id,
                remote_user_id,
            )
            registered_user_id = await self._datastore.get_user_by_external_id(
                self._auth_provider_id, remote_user_id
            )
            if registered_user_id is not None:
                logger.info("Found existing mapping %s", registered_user_id)
                return registered_user_id

            # backwards-compatibility hack: see if there is an existing user with a
            # suitable mapping from the uid

            # figure out a new mxid for this user
            base_mxid_localpart = userinfo["preferred_username"]

            suffix = 0
            while True:
                localpart = base_mxid_localpart + (str(suffix) if suffix else "")
                if not await self._datastore.get_users_by_id_case_insensitive(
                    UserID(localpart, self._hostname).to_string()
                ):
                    break
                suffix += 1
            logger.info("Allocating mxid for new user with localpart %s", localpart)

            registered_user_id = await self._registration_handler.register_user(
                localpart=localpart, default_display_name=displayName
            )
            await self._datastore.record_user_external_id(
                self._auth_provider_id, remote_user_id, registered_user_id
            )
            return registered_user_id

    def expire_sessions(self):
        expire_before = self._clock.time_msec() - self._saml2_session_lifetime
        to_expire = set()
        for reqid, data in self._outstanding_requests_dict.items():
            if data.creation_time < expire_before:
                to_expire.add(reqid)
        for reqid in to_expire:
            logger.debug("Expiring session id %s", reqid)
            del self._outstanding_requests_dict[reqid]


@attr.s
class Saml2SessionData:
    """Data we track about SAML2 sessions"""

    # time the session was created, in milliseconds
    creation_time = attr.ib()
