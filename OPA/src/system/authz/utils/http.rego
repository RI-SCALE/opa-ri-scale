package system.authz.utils

import rego.v1

_update_methods := [
	"PUT",
	"PATCH",
	"DELETE"
]

_query_methods := [
	"GET",
	"HEAD",
	"POST"
]

_safe_http_get(url) := resp if {
    resp := http.send({
        "method": "get",
        "url": url,
        "cache": true,
        "enable_redirect": true,
    })
    resp.status_code >= 200
    resp.status_code < 400
}