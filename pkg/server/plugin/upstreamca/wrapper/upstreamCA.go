package wrapper

import (
	"context"

	"github.com/spiffe/spire/pkg/server/plugin/upstreamauthority"
	"github.com/spiffe/spire/pkg/server/plugin/upstreamca"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type UpstreamCA struct {
	upstreamCA upstreamca.UpstreamCA
}

func New(upstreamCA upstreamca.UpstreamCA) *UpstreamCA {
	return &UpstreamCA{upstreamCA: upstreamCA}
}

func (w *UpstreamCA) MintX509CA(ctx context.Context, request *upstreamauthority.MintX509CARequest) (*upstreamauthority.MintX509CAResponse, error) {
	req := &upstreamca.SubmitCSRRequest{
		Csr:          request.Csr,
		PreferredTtl: request.PreferredTtl,
	}

	resp, err := w.upstreamCA.SubmitCSR(ctx, req)
	if err != nil {
		return nil, err
	}

	return &upstreamauthority.MintX509CAResponse{
		UpstreamX509Roots: [][]byte{resp.SignedCertificate.Bundle},
		X509CaChain:       [][]byte{resp.SignedCertificate.CertChain},
	}, nil
}

func (w *UpstreamCA) PublishJWTKey(ctx context.Context, request *upstreamauthority.PublishJWTKeyRequest) (*upstreamauthority.PublishJWTKeyResponse, error) {
	return nil, status.Error(codes.Unimplemented, "Method is not implemented")
}

func (w *UpstreamCA) PublishX509CA(ctx context.Context, request *upstreamauthority.PublishX509CARequest) (*upstreamauthority.PublishX509CAResponse, error) {
	return nil, status.Error(codes.Unimplemented, "Method is not implemented")
}
