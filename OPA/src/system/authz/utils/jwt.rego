package system.authz.utils

import rego.v1

import data.system.authz.utils._sanitized_url

default _well_known_endpoint(_) := null

_payload(token) := p if {
 	[_, p, _] := io.jwt.decode(token) 
}

_well_known_endpoint(host) := body if {
    oidc := _safe_http_get(sprintf("%s/%s", [_sanitized_url(host), ".well-known/openid-configuration"]))
    body := oidc.body
} else := body if {
    oauth := _safe_http_get(sprintf("%s/%s", [_sanitized_url(host), ".well-known/oauth-authorization-server "]))
    body := oauth.body
}
