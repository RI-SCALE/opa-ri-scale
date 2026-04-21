package system.authz

import rego.v1

import data.system.authz.match.matched_policy as policy
import data.system.authz.utils._query_methods
import data.system.authz.utils._update_methods
import data.system.authz.utils._payload
import data.system.authz.introspect.introspection_response

default allow := {
	"allowed": false,
	"reason": "Unauthorized resource access",
}

allow := {"allowed": true} if {
	introspection_response(policy.client_id, policy.client_secret).active
	input.method in _query_methods
}

allow := {"allowed": true} if {
	introspection_response(policy.client_id, policy.client_secret).active
	some group in _payload(input.identity)["wlcg.groups"]
	group in policy.groups
	input.method in _update_methods
}

allow := {"allowed": true} if {
	introspection_response(policy.client_id, policy.client_secret).active
	some group in _payload(input.identity).entitlements
	group in policy.groups
	input.method in _update_methods
}

allow := {"allowed": false, "reason": reason} if {
	not input.identity
	reason := "Missing bearer token"
}
