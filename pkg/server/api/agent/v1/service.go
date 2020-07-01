package agent

import (
	"context"
	"crypto/x509"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/nodeutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/pkg/server/plugin/datastore"
	"github.com/spiffe/spire/proto/spire-next/api/server/agent/v1"
	"github.com/spiffe/spire/proto/spire-next/types"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RegisterService registers the agent service on the gRPC server/
func RegisterService(s *grpc.Server, service *Service) {
	agent.RegisterAgentServer(s, service)
}

// Config is the service configuration
type Config struct {
	Datastore datastore.DataStore
	ServerCA  ca.ServerCA
}

// New creates a new agent service
func New(config Config) *Service {
	return &Service{
		ds: config.Datastore,
	}
}

// Service implements the v1 agent service
type Service struct {
	ca ca.ServerCA
	ds datastore.DataStore
}

func (s *Service) ListAgents(ctx context.Context, req *agent.ListAgentsRequest) (*agent.ListAgentsResponse, error) {
	log := rpccontext.Logger(ctx)

	listReq := &datastore.ListAttestedNodesRequest{}

	if req.OutputMask == nil || req.OutputMask.Selectors {
		listReq.FetchSelectors = true
	}
	// Parse proto filter into datastore request
	if req.Filter != nil {
		filter := req.Filter
		listReq.ByAttestationType = filter.ByAttestationType
		listReq.ByBanned = filter.ByBanned

		if filter.BySelectorMatch != nil {
			selectors, err := api.SelectorsFromProto(filter.BySelectorMatch.Selectors)
			if err != nil {
				log.WithError(err).Error("Failed to parse selectors")
				return nil, status.Errorf(codes.InvalidArgument, "failed to parse selectors: %v", err)
			}
			listReq.BySelectorMatch = &datastore.BySelectors{
				Match:     datastore.BySelectors_MatchBehavior(filter.BySelectorMatch.Match),
				Selectors: selectors,
			}
		}
	}

	// Set pagination parameters
	if req.PageSize > 0 {
		listReq.Pagination = &datastore.Pagination{
			PageSize: req.PageSize,
			Token:    req.PageToken,
		}
	}

	dsResp, err := s.ds.ListAttestedNodes(ctx, listReq)
	if err != nil {
		log.WithError(err).Error("Failed to list agents")
		return nil, status.Errorf(codes.Internal, "failed to list agents: %v", err)
	}

	resp := &agent.ListAgentsResponse{}

	if dsResp.Pagination != nil {
		resp.NextPageToken = dsResp.Pagination.Token
	}

	// Parse nodes into proto and apply output mask
	for _, node := range dsResp.Nodes {
		a, err := api.ProtoFromAttestedNode(node)
		if err != nil {
			log.WithError(err).WithField(telemetry.SPIFFEID, node.SpiffeId).Warn("Unable to parse attested node")
			continue
		}

		applyMask(a, req.OutputMask)
		resp.Agents = append(resp.Agents, a)
	}

	return resp, nil
}

func (s *Service) GetAgent(ctx context.Context, req *agent.GetAgentRequest) (*types.Agent, error) {
	return nil, status.Error(codes.Unimplemented, "method not implemented")
}

func (s *Service) DeleteAgent(ctx context.Context, req *agent.DeleteAgentRequest) (*empty.Empty, error) {
	return nil, status.Error(codes.Unimplemented, "method not implemented")
}

func (s *Service) BanAgent(ctx context.Context, req *agent.BanAgentRequest) (*empty.Empty, error) {
	return nil, status.Error(codes.Unimplemented, "method not implemented")
}

func (s *Service) AttestAgent(stream agent.Agent_AttestAgentServer) error {
	return status.Error(codes.Unimplemented, "method not implemented")
}

func (s *Service) RenewAgent(stream agent.Agent_RenewAgentServer) error {
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()

	log := rpccontext.Logger(ctx)

	if err := rpccontext.RateLimit(ctx, 1); err != nil {
		log.WithError(err).Error("Rejecting request due to renew agent rate limiting")
		return err
	}

	callerID, ok := rpccontext.CallerID(ctx)
	if !ok {
		log.Error("Caller ID missing from request context")
		return status.Error(codes.InvalidArgument, "caller ID missing from request context")
	}

	req, err := stream.Recv()
	if err != nil {
		log.WithError(err).Error("Failed to receive request from stream")
		return status.Error(codes.InvalidArgument, err.Error())
	}

	step, ok := req.Step.(*agent.RenewAgentRequest_Params)
	if !ok {
		log.Error("Invalid argument: unnexpected step type: %T", step)
		return status.Errorf(codes.InvalidArgument, "unnexpected step type: %T", step)
	}

	// Get attested node
	// TODO: once mask is merged, may I just validate attested node is not banned once?
	node, err := s.fetchAttestedNode(ctx, &callerID)
	if err != nil {
		log.WithError(err).Error("Failed to fetch attested node")
		return err
	}

	x509Svid, err := s.signSvid(ctx, &callerID, step, log)
	if err != nil {
		return err
	}

	var certChain [][]byte
	for _, cert := range x509Svid {
		certChain = append(certChain, cert.Raw)
	}

	// Send response with new X509 SVID
	if err := stream.Send(&agent.RenewAgentResponse{
		Svid: &types.X509SVID{
			Id:        api.ProtoFromID(callerID),
			ExpiresAt: x509Svid[0].NotAfter.Unix(),
			CertChain: certChain,
		},
	}); err != nil {
		log.WithError(err).Error("Failed to send response")
		return status.Errorf(codes.Internal, "failed to send response: %v", err)
	}

	// TODO: May I use Mask here?
	if _, err := s.ds.UpdateAttestedNode(ctx, &datastore.UpdateAttestedNodeRequest{
		SpiffeId:            node.SpiffeId,
		CertNotAfter:        node.CertNotAfter,
		CertSerialNumber:    node.CertSerialNumber,
		NewCertNotAfter:     x509Svid[0].NotAfter.Unix(),
		NewCertSerialNumber: x509Svid[0].SerialNumber.String(),
	}); err != nil {
		log.WithError(err).Error("Failed to update attested node")
		return status.Errorf(codes.Internal, "failed to update attested node: %v", err)
	}

	// Wait until get ACK
	step, ok = req.Step.(*agent.RenewAgentRequest_Params)
	if !ok {
		log.Error("Invalid argument: unnexpected step type: %T", step)
		return status.Errorf(codes.InvalidArgument, "unnexpected step type: %T", step)
	}

	// TODO: may I use mask here?
	// TODO: may I fetch node again?
	if _, err := s.ds.UpdateAttestedNode(ctx, &datastore.UpdateAttestedNodeRequest{
		SpiffeId:         node.SpiffeId,
		CertNotAfter:     node.NewCertNotAfter,
		CertSerialNumber: node.NewCertSerialNumber,
	}); err != nil {
		log.WithError(err).Error("Failed to udpate attested node")
		return status.Errorf(codes.Internal, "failed to update attested node")
	}

	return nil
}

func (s *Service) signSvid(ctx context.Context, agentID *spiffeid.ID, step *agent.RenewAgentRequest_Params, log logrus.FieldLogger) ([]*x509.Certificate, error) {
	if step.Params == nil {
		log.Error("Invalid argument: missing params")
		return nil, status.Error(codes.InvalidArgument, "missing params")
	}

	if len(step.Params.Csr) == 0 {
		log.Error("Invalid argument: missing csr")
		return nil, status.Error(codes.InvalidArgument, "missing csr")
	}

	csr, err := x509.ParseCertificateRequest(step.Params.Csr)
	if err != nil {
		log.WithError(err).Error("Failed to parse csr")
		return nil, status.Errorf(codes.InvalidArgument, "failed to parse csr: %v", err)
	}

	// Sign a new X509 SVID
	x509Svid, err := s.ca.SignX509SVID(ctx, ca.X509SVIDParams{
		SpiffeID:  agentID.String(),
		PublicKey: csr.PublicKey,
	})
	if err != nil {
		log.WithError(err).Error("Failed to sign X509 SVID")
		return nil, status.Errorf(codes.Internal, "failed to sign X509 SVID: %v", err)
	}

	return x509Svid, nil
}

func (s *Service) fetchAttestedNode(ctx context.Context, agentID *spiffeid.ID) (*common.AttestedNode, error) {
	attestedNodeResp, err := s.ds.FetchAttestedNode(ctx, &datastore.FetchAttestedNodeRequest{
		SpiffeId: agentID.String(),
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to fetch attested node: %v", err)
	}

	node := attestedNodeResp.Node
	if node == nil {
		return nil, status.Error(codes.Internal, "no attested node found")
	}

	// Verify that node is not banned
	if nodeutil.IsAgentBanned(node) {
		// TODO: what error return here?
		return nil, status.Error(codes.Internal, "agent banned")
	}

	return attestedNodeResp.Node, nil
}

func (s *Service) CreateJoinToken(ctx context.Context, req *agent.CreateJoinTokenRequest) (*types.JoinToken, error) {
	return nil, status.Error(codes.Unimplemented, "method not implemented")
}

func applyMask(a *types.Agent, mask *types.AgentMask) { //nolint: unused,deadcode
	if mask == nil {
		return
	}
	if !mask.AttestationType {
		a.AttestationType = ""
	}

	if !mask.X509SvidSerialNumber {
		a.X509SvidSerialNumber = ""
	}

	if !mask.X509SvidExpiresAt {
		a.X509SvidExpiresAt = 0
	}

	if !mask.Selectors {
		a.Selectors = nil
	}

	if !mask.Banned {
		a.Banned = false
	}
}
