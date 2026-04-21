package system.authz.introspect

import rego.v1

import data.system.authz.utils._payload
import data.system.authz.utils._well_known_endpoint

introspection_response(client_id, client_secret) := body if {
    url := _well_known_endpoint(_payload(input.identity).iss).introspection_endpoint
    token := sprintf("token=%s", [input.identity])

    resp := _safe_http_introspect(url, token, client_id, client_secret)
    body := resp.body
}

_safe_http_introspect(url, token, client_id, client_secret) := resp if{
    basic_encoded_credentials := base64.encode(sprintf("%s:%s", [client_id, client_secret]))

    resp := http.send({
		"method": "post",
		"url": url,
        "headers": {
            "Authorization": sprintf("Basic %s", [basic_encoded_credentials]),
            "Content-Type": "application/x-www-form-urlencoded"
        },
        "raw_body": token,
		"enable_redirect": true,
        "force_json_decode": true,
	})
    resp.status_code >= 200
    resp.status_code < 400
}