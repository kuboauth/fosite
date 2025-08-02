// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/ory/x/errorsx"
	"github.com/ory/x/otelx"
	"go.opentelemetry.io/otel/trace"
)

func (f *Fosite) NewAuthorizeResponse(ctx context.Context, ar AuthorizeRequester, session Session) (_ AuthorizeResponder, err error) {
	ctx, span := trace.SpanFromContext(ctx).TracerProvider().Tracer("github.com/ory/fosite").Start(ctx, "Fosite.NewAuthorizeResponse")
	defer otelx.End(span, &err)

	fmt.Printf("************************* NewAuthorizeResponse()1\n")

	var resp = &AuthorizeResponse{
		Header:     http.Header{},
		Parameters: url.Values{},
	}

	ctx = context.WithValue(ctx, AuthorizeRequestContextKey, ar)
	ctx = context.WithValue(ctx, AuthorizeResponseContextKey, resp)

	ar.SetSession(session)
	for _, h := range f.Config.GetAuthorizeEndpointHandlers(ctx) {

		fmt.Printf("************************* NewAuthorizeResponse()1-a  %v\n", h.GetName())
		if err := h.HandleAuthorizeEndpointRequest(ctx, ar, resp); err != nil {
			fmt.Printf("************************* NewAuthorizeResponse()1-b ERROR=%v\n", err)
			return nil, err
		}
	}
	fmt.Printf("************************* NewAuthorizeResponse2()\n")

	if !ar.DidHandleAllResponseTypes() {
		return nil, errorsx.WithStack(ErrUnsupportedResponseType)
	}
	fmt.Printf("************************* NewAuthorizeResponse3()\n")

	if ar.GetDefaultResponseMode() == ResponseModeFragment && ar.GetResponseMode() == ResponseModeQuery {
		return nil, ErrUnsupportedResponseMode.WithHintf("Insecure response_mode '%s' for the response_type '%s'.", ar.GetResponseMode(), ar.GetResponseTypes())
	}
	fmt.Printf("************************* NewAuthorizeResponse4()\n")

	return resp, nil
}
