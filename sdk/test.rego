package sas.types.authz

import future.keywords.if
import future.keywords.in

default allow := false

default authenticatedUser := false

default currentUser := ""

allow if {
	grant
}

claims := payload if {
	io.jwt.verify_rs256(input.token, opa.runtime().config.env.SAS_OAUTH_TOKEN_VERIFY_KEY)
	[_, payload, _] := io.jwt.decode(input.token)
}

authenticatedUser := a if {
	claims
	a := count(claims) > 0
}

currentUser := u if {
	not claims.user_name
	u := claims.client_id
}

currentUser := claims.user_name

grant if {
	input.request.permission in ["read"]
	input.request.uri = "/types/"
	authenticatedUser = true
}
