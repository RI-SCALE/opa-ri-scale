package system.authz

import rego.v1

import data.system.authz.tokens as tokens

default allow := {
	"allowed": false,
	"reason": "Unauthorized resource access",
}

allow := {"allowed": true} if {
    some token in tokens
	_payload(input.identity).iss == token.issuer
	input.method in _query_methods
}

allow := {"allowed": true} if {
    some token in tokens
	_payload(input.identity).iss == token.issuer
	some group in _payload(input.identity)["wlcg.groups"]
	group in token.groups
	input.method in _update_methods
}

allow := {"allowed": true} if {
    some token in tokens
	_payload(input.identity).iss == token.issuer
	some group in _payload(input.identity).entitlements
	group in token.groups
	input.method in _update_methods
}

allow := {"allowed": false, "reason": reason} if {
	not input.identity
	reason := "Missing bearer token"
}
