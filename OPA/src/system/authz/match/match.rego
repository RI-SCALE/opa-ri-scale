package system.authz.match

import rego.v1

import data.system.authz.utils._payload
import data.system.authz.policy.tokens as tokens

default token_is_matched(_) := false
default matched_token_issuer(_) := null
default matched_policy := null

token_is_matched(policy) if {
	_payload(input.identity).iss == policy.issuer
}

matched_token_issuer(policy) := iss if {
    token_is_matched(policy)
    iss := _payload(input.identity).iss
}

matched_policy := policy if {
    some policy in tokens
    policy.issuer == matched_token_issuer(policy)
}
