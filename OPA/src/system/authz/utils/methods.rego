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