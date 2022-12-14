// Code generated by goa v3.10.2, DO NOT EDIT.
//
// login HTTP server encoders and decoders
//
// Command:
// $ goa gen github.com/codeready-toolchain/sandbox-auth/design

package server

import (
	"context"
	"net/http"

	login "github.com/codeready-toolchain/sandbox-auth/gen/login"
	goahttp "goa.design/goa/v3/http"
)

// EncodeLoginResponse returns an encoder for responses returned by the login
// login endpoint.
func EncodeLoginResponse(encoder func(context.Context, http.ResponseWriter) goahttp.Encoder) func(context.Context, http.ResponseWriter, interface{}) error {
	return func(ctx context.Context, w http.ResponseWriter, v interface{}) error {
		res, _ := v.(*login.LoginResult)
		if res.Outcome != nil && *res.Outcome == "redirect" {
			enc := encoder(ctx, w)
			body := NewLoginTemporaryRedirectResponseBody(res)
			w.Header().Set("Location", *res.Location)
			w.WriteHeader(http.StatusTemporaryRedirect)
			return enc.Encode(body)
		}
		enc := encoder(ctx, w)
		body := NewLoginUnauthorizedResponseBody(res)
		w.WriteHeader(http.StatusUnauthorized)
		return enc.Encode(body)
	}
}

// DecodeLoginRequest returns a decoder for requests sent to the login login
// endpoint.
func DecodeLoginRequest(mux goahttp.Muxer, decoder func(*http.Request) goahttp.Decoder) func(*http.Request) (interface{}, error) {
	return func(r *http.Request) (interface{}, error) {
		var (
			redirect  *string
			apiClient *string
			referer   *string
		)
		redirectRaw := r.URL.Query().Get("redirect")
		if redirectRaw != "" {
			redirect = &redirectRaw
		}
		apiClientRaw := r.URL.Query().Get("api_client")
		if apiClientRaw != "" {
			apiClient = &apiClientRaw
		}
		refererRaw := r.Header.Get("Referer")
		if refererRaw != "" {
			referer = &refererRaw
		}
		payload := NewLoginCriteria(redirect, apiClient, referer)

		return payload, nil
	}
}

// EncodeCallbackResponse returns an encoder for responses returned by the
// login callback endpoint.
func EncodeCallbackResponse(encoder func(context.Context, http.ResponseWriter) goahttp.Encoder) func(context.Context, http.ResponseWriter, interface{}) error {
	return func(ctx context.Context, w http.ResponseWriter, v interface{}) error {
		res, _ := v.(*login.LoginResult)
		if res.Outcome != nil && *res.Outcome == "redirect" {
			enc := encoder(ctx, w)
			body := NewCallbackTemporaryRedirectResponseBody(res)
			w.Header().Set("Location", *res.Location)
			w.WriteHeader(http.StatusTemporaryRedirect)
			return enc.Encode(body)
		}
		enc := encoder(ctx, w)
		body := NewCallbackUnauthorizedResponseBody(res)
		w.WriteHeader(http.StatusUnauthorized)
		return enc.Encode(body)
	}
}

// DecodeCallbackRequest returns a decoder for requests sent to the login
// callback endpoint.
func DecodeCallbackRequest(mux goahttp.Muxer, decoder func(*http.Request) goahttp.Decoder) func(*http.Request) (interface{}, error) {
	return func(r *http.Request) (interface{}, error) {
		var (
			code  *string
			state *string
		)
		codeRaw := r.URL.Query().Get("code")
		if codeRaw != "" {
			code = &codeRaw
		}
		stateRaw := r.URL.Query().Get("state")
		if stateRaw != "" {
			state = &stateRaw
		}
		payload := NewCallbackLoginCallbackCriteria(code, state)

		return payload, nil
	}
}