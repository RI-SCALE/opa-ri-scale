package dep.match_test

import rego.v1

_odrl := {"policies": [
	{"uid": "p1", "type": "Set", "prohibition": [{"action": "read", "target": "t", "assignee": "banned"}]},
	{"uid": "p2", "type": "Set", "permission": [{"action": "write", "target": "t", "assignee": "admin",
		"constraint": [{"leftOperand": "acr", "operator": "eq", "rightOperand": "mfa"}]}]},
]}

test_prohibition_denies if {
	not data.dep.allow with data.dep.odrl as _odrl
		with input as {"action": "read", "resource": {"id": "t"}, "token": {"entitlements": ["banned"]}}
}

test_failing_constraint_denies if {
	not data.dep.allow with data.dep.odrl as _odrl
		with input as {"action": "write", "resource": {"id": "t"}, "token": {"entitlements": ["admin"], "acr": "none"}}
}

test_satisfied_constraint_allows if {
	data.dep.allow with data.dep.odrl as _odrl
		with input as {"action": "write", "resource": {"id": "t"}, "token": {"entitlements": ["admin"], "acr": "mfa"}}
}
