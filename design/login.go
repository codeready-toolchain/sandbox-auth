package design

import (
	. "goa.design/goa/v3/dsl"
)

var LoginCriteria = Type("LoginCriteria", func() {
	Attribute("referer", String, "Referer header value")
	Attribute("redirect", String, "URL to be redirected to after logging in successfully")
	Attribute("api_client", String, "The name of the api client which is requesting a token")
})

var LoginResult = Type("LoginResult", func() {
	Attribute("outcome", String, "Login Result Outcome")
	Attribute("location", String, "Location to redirect to for authentication")
})

var CallbackCriteria = Type("LoginCallbackCriteria", func() {
	Attribute("code", String, "Authorization Code")
	Attribute("state", String, "State value")
})

var _ = Service("login", func() {
	Description("Login Service")

	Method("login", func() {
		Description("Login endpoint sets up the user for authentication and redirects them to the identity provider")
		Payload(LoginCriteria)
		Result(LoginResult)
		HTTP(func() {
			Header("referer:Referer", String)
			GET("/v1/login")
			Params(func() {
				Param("redirect")
				Param("api_client")
			})
			Response(StatusUnauthorized)
			Response(StatusTemporaryRedirect, func() {
				Header("location:Location")
				Tag("outcome", "redirect")
			})
			Response(StatusInternalServerError)
			Response(StatusBadRequest)
		})
	})

	Method("callback", func() {
		Description("Callback endpoint that receives authorization code from identity provider")
		Payload(CallbackCriteria)
		Result(LoginResult)
		HTTP(func() {
			GET("/v1/login/callback")
			Params(func() {
				Param("code")
				Param("state")
			})
			Response(StatusUnauthorized)
			Response(StatusTemporaryRedirect, func() {
				Header("location:Location")
				Tag("outcome", "redirect")
			})
			Response(StatusInternalServerError)
			Response(StatusBadRequest)
		})
	})

})
