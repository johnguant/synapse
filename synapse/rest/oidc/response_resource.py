# -*- coding: utf-8 -*-
#
# Copyright 2018 New Vector Ltd
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

from synapse.http.server import DirectServeResource, wrap_html_request_handler


class OIDCResponseResource(DirectServeResource):
    """A Twisted web resource which handles the OIDC response"""

    isLeaf = 1

    def __init__(self, hs):
        super().__init__()
        self._oidc_handler = hs.get_oidc_handler()

    @wrap_html_request_handler
    async def _async_render_GET(self, request):
        return await self._oidc_handler.handle_oidc_response(request)
