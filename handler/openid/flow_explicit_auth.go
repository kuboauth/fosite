// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"
	"fmt"

	"github.com/ory/x/errorsx"

	"github.com/ory/fosite"
)

type OpenIDConnectExplicitHandler struct {
	// OpenIDConnectRequestStorage is the storage for open id connect sessions.
	OpenIDConnectRequestStorage   OpenIDConnectRequestStorage
	OpenIDConnectRequestValidator *OpenIDConnectRequestValidator

	Config interface {
		fosite.IDTokenLifespanProvider
	}

	*IDTokenHandleHelper
}

var _ fosite.AuthorizeEndpointHandler = (*OpenIDConnectExplicitHandler)(nil)
var _ fosite.TokenEndpointHandler = (*OpenIDConnectExplicitHandler)(nil)

var oidcParameters = []string{"grant_type",
	"max_age",
	"prompt",
	"acr_values",
	"id_token_hint",
	"nonce",
}

func (c *OpenIDConnectExplicitHandler) GetName() string {
	return "OpenIDConnectExplicitHandler"
}

func (c *OpenIDConnectExplicitHandler) HandleAuthorizeEndpointRequest(ctx context.Context, ar fosite.AuthorizeRequester, resp fosite.AuthorizeResponder) error {

	fmt.Printf("##################### OpenIDConnectExplicitHandler.HandleAuthorizeEndpointRequest()-1\n")

	if !(ar.GetGrantedScopes().Has("openid") && ar.GetResponseTypes().ExactOne("code")) {
		fmt.Printf("##################### OpenIDConnectExplicitHandler.HandleAuthorizeEndpointRequest()-2  GetGrantedScopes:%v  GetResponseTypes:%v\n", ar.GetGrantedScopes(), ar.GetResponseTypes())
		return nil
	}

	//if !ar.GetClient().GetResponseTypes().Has("id_token", "code") {
	//	return errorsx.WithStack(fosite.ErrInvalidRequest.WithDebug("The client is not allowed to use response type id_token and code"))
	//}

	if len(resp.GetCode()) == 0 {
		fmt.Printf("##################### OpenIDConnectExplicitHandler.HandleAuthorizeEndpointRequest()-3\n")
		return errorsx.WithStack(fosite.ErrMisconfiguration.WithDebug("The authorization code has not been issued yet, indicating a broken code configuration."))
	}

	// This ensures that the 'redirect_uri' parameter is present for OpenID Connect 1.0 authorization requests as per:
	//
	// Authorization Code Flow - https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
	// Implicit Flow - https://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthRequest
	// Hybrid Flow - https://openid.net/specs/openid-connect-core-1_0.html#HybridAuthRequest
	//
	// Note: as per the Hybrid Flow documentation the Hybrid Flow has the same requirements as the Authorization Code Flow.
	rawRedirectURI := ar.GetRequestForm().Get("redirect_uri")
	if len(rawRedirectURI) == 0 {
		fmt.Printf("##################### OpenIDConnectExplicitHandler.HandleAuthorizeEndpointRequest()-4\n")
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("The 'redirect_uri' parameter is required when using OpenID Connect 1.0."))
	}

	if err := c.OpenIDConnectRequestValidator.ValidatePrompt(ctx, ar); err != nil {
		fmt.Printf("##################### OpenIDConnectExplicitHandler.HandleAuthorizeEndpointRequest()-5\n")
		return err
	}

	if err := c.OpenIDConnectRequestStorage.CreateOpenIDConnectSession(ctx, resp.GetCode(), ar.Sanitize(oidcParameters)); err != nil {
		fmt.Printf("##################### OpenIDConnectExplicitHandler.HandleAuthorizeEndpointRequest()-6\n")
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	// there is no need to check for https, because it has already been checked by core.explicit

	fmt.Printf("##################### OpenIDConnectExplicitHandler.HandleAuthorizeEndpointRequest()-7\n")
	return nil
}
