package agent_test

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/agent/v1"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	agentpb "github.com/spiffe/spire/proto/spire-next/api/server/agent/v1"
	"github.com/spiffe/spire/proto/spire-next/types"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/proto/spire/server/datastore"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/fakes/fakeserverca"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testkey"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

var (
	ctx     = context.Background()
	td      = spiffeid.RequireTrustDomainFromString("example.org")
	agentID = td.NewID("agent")
)

func TestListAgents(t *testing.T) {
	test := setupServiceTest(t)
	defer test.Cleanup()

	notAfter := time.Now().Add(-time.Minute).Unix()
	newNoAfter := time.Now().Add(time.Minute).Unix()
	node1ID := spiffeid.Must("example.org", "node1")
	node1 := &common.AttestedNode{
		SpiffeId:            node1ID.String(),
		AttestationDataType: "t1",
		CertSerialNumber:    "badcafe",
		CertNotAfter:        notAfter,
		NewCertNotAfter:     newNoAfter,
		NewCertSerialNumber: "new badcafe",
		Selectors: []*common.Selector{
			{Type: "a", Value: "1"},
			{Type: "b", Value: "2"},
		},
	}
	_, err := test.ds.CreateAttestedNode(ctx, &datastore.CreateAttestedNodeRequest{
		Node: node1,
	})
	require.NoError(t, err)
	_, err = test.ds.SetNodeSelectors(ctx, &datastore.SetNodeSelectorsRequest{
		Selectors: &datastore.NodeSelectors{
			SpiffeId:  node1.SpiffeId,
			Selectors: node1.Selectors},
	})
	require.NoError(t, err)

	node2ID := spiffeid.Must("example.org", "node2")
	node2 := &common.AttestedNode{
		SpiffeId:            node2ID.String(),
		AttestationDataType: "t2",
		CertSerialNumber:    "deadbeef",
		CertNotAfter:        notAfter,
		NewCertNotAfter:     newNoAfter,
		NewCertSerialNumber: "new deadbeef",
		Selectors: []*common.Selector{
			{Type: "a", Value: "1"},
			{Type: "c", Value: "3"},
		},
	}
	_, err = test.ds.CreateAttestedNode(ctx, &datastore.CreateAttestedNodeRequest{
		Node: node2,
	})
	require.NoError(t, err)
	_, err = test.ds.SetNodeSelectors(ctx, &datastore.SetNodeSelectorsRequest{
		Selectors: &datastore.NodeSelectors{
			SpiffeId:  node2.SpiffeId,
			Selectors: node2.Selectors},
	})
	require.NoError(t, err)

	node3ID := spiffeid.Must("example.org", "node3")
	node3 := &common.AttestedNode{
		SpiffeId:            node3ID.String(),
		AttestationDataType: "t3",
		CertSerialNumber:    "",
		CertNotAfter:        notAfter,
		NewCertNotAfter:     newNoAfter,
		NewCertSerialNumber: "",
	}
	_, err = test.ds.CreateAttestedNode(ctx, &datastore.CreateAttestedNodeRequest{
		Node: node3,
	})
	require.NoError(t, err)

	for _, tt := range []struct {
		name string

		code       codes.Code
		dsError    error
		err        string
		expectLogs []spiretest.LogEntry
		expectResp *agentpb.ListAgentsResponse
		req        *agentpb.ListAgentsRequest
	}{
		{
			name: "success",
			req: &agentpb.ListAgentsRequest{
				OutputMask: &types.AgentMask{AttestationType: true},
			},
			expectResp: &agentpb.ListAgentsResponse{
				Agents: []*types.Agent{
					{Id: api.ProtoFromID(node1ID), AttestationType: "t1"},
					{Id: api.ProtoFromID(node2ID), AttestationType: "t2"},
					{Id: api.ProtoFromID(node3ID), AttestationType: "t3"},
				},
			},
		},
		{
			name: "no mask",
			req:  &agentpb.ListAgentsRequest{},
			expectResp: &agentpb.ListAgentsResponse{
				Agents: []*types.Agent{
					{
						Id:                   api.ProtoFromID(node1ID),
						AttestationType:      "t1",
						Banned:               false,
						X509SvidExpiresAt:    notAfter,
						X509SvidSerialNumber: "badcafe",
						Selectors: []*types.Selector{
							{Type: "a", Value: "1"},
							{Type: "b", Value: "2"},
						},
					},
					{
						Id:                   api.ProtoFromID(node2ID),
						AttestationType:      "t2",
						Banned:               false,
						X509SvidExpiresAt:    notAfter,
						X509SvidSerialNumber: "deadbeef",
						Selectors: []*types.Selector{
							{Type: "a", Value: "1"},
							{Type: "c", Value: "3"},
						},
					},
					{
						Id:                   api.ProtoFromID(node3ID),
						AttestationType:      "t3",
						Banned:               true,
						X509SvidExpiresAt:    notAfter,
						X509SvidSerialNumber: "",
					},
				},
			},
		},
		{
			name: "mask all false",
			req: &agentpb.ListAgentsRequest{
				OutputMask: &types.AgentMask{},
			},
			expectResp: &agentpb.ListAgentsResponse{
				Agents: []*types.Agent{
					{Id: api.ProtoFromID(node1ID)},
					{Id: api.ProtoFromID(node2ID)},
					{Id: api.ProtoFromID(node3ID)},
				},
			},
		},
		{
			name: "by attestation type",
			req: &agentpb.ListAgentsRequest{
				OutputMask: &types.AgentMask{},
				Filter: &agentpb.ListAgentsRequest_Filter{
					ByAttestationType: "t1",
				},
			},
			expectResp: &agentpb.ListAgentsResponse{
				Agents: []*types.Agent{
					{Id: api.ProtoFromID(node1ID)},
				},
			},
		},
		{
			name: "by banned true",
			req: &agentpb.ListAgentsRequest{
				OutputMask: &types.AgentMask{},
				Filter: &agentpb.ListAgentsRequest_Filter{
					ByBanned: &wrappers.BoolValue{Value: true},
				},
			},
			expectResp: &agentpb.ListAgentsResponse{
				Agents: []*types.Agent{
					{Id: api.ProtoFromID(node3ID)},
				},
			},
		},
		{
			name: "by banned false",
			req: &agentpb.ListAgentsRequest{
				OutputMask: &types.AgentMask{},
				Filter: &agentpb.ListAgentsRequest_Filter{
					ByBanned: &wrappers.BoolValue{Value: false},
				},
			},
			expectResp: &agentpb.ListAgentsResponse{
				Agents: []*types.Agent{
					{Id: api.ProtoFromID(node1ID)},
					{Id: api.ProtoFromID(node2ID)},
				},
			},
		},
		{
			name: "by selectors",
			req: &agentpb.ListAgentsRequest{
				OutputMask: &types.AgentMask{},
				Filter: &agentpb.ListAgentsRequest_Filter{
					BySelectorMatch: &types.SelectorMatch{
						Match: types.SelectorMatch_MATCH_EXACT,
						Selectors: []*types.Selector{
							{Type: "a", Value: "1"},
							{Type: "b", Value: "2"},
						},
					},
				},
			},
			expectResp: &agentpb.ListAgentsResponse{
				Agents: []*types.Agent{
					{Id: api.ProtoFromID(node1ID)},
				},
			},
		},
		{
			name: "with pagination",
			req: &agentpb.ListAgentsRequest{
				OutputMask: &types.AgentMask{},
				PageSize:   2,
			},
			expectResp: &agentpb.ListAgentsResponse{
				Agents: []*types.Agent{
					{Id: api.ProtoFromID(node1ID)},
					{Id: api.ProtoFromID(node2ID)},
				},
				NextPageToken: "2",
			},
		},
		{
			name: "malformed selectors",
			req: &agentpb.ListAgentsRequest{
				Filter: &agentpb.ListAgentsRequest_Filter{
					BySelectorMatch: &types.SelectorMatch{
						Selectors: []*types.Selector{{Value: "1"}},
					},
				},
			},
			code: codes.InvalidArgument,
			err:  "failed to parse selectors: missing selector type",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to parse selectors",
					Data: logrus.Fields{
						logrus.ErrorKey: "missing selector type",
					},
				},
			},
		},
		{
			name:    "ds fails",
			req:     &agentpb.ListAgentsRequest{},
			code:    codes.Internal,
			dsError: errors.New("some error"),
			err:     "failed to list agents: some error",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Failed to list agents",
					Data: logrus.Fields{
						logrus.ErrorKey: "some error",
					},
				},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test.logHook.Reset()
			test.ds.SetNextError(tt.dsError)

			resp, err := test.client.ListAgents(ctx, tt.req)

			spiretest.AssertLogs(t, test.logHook.AllEntries(), tt.expectLogs)
			if tt.err != "" {
				spiretest.RequireGRPCStatusContains(t, err, tt.code, tt.err)
				require.Nil(t, resp)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, resp)

			spiretest.RequireProtoEqual(t, tt.expectResp, resp)
		})
	}
}

func TestRenewAgent(t *testing.T) {
	testKey := testkey.MustEC256()
	agentIDType := &types.SPIFFEID{TrustDomain: "examples.org", Path: "/agent"}

	defaultNode := &common.AttestedNode{
		SpiffeId:            agentID.String(),
		AttestationDataType: "t",
		CertNotAfter:        12345,
		CertSerialNumber:    "6789",
		Selectors: []*common.Selector{
			{Type: "a", Value: "1"},
		},
	}

	for _, tt := range []struct {
		name string

		code       codes.Code
		dsError    error
		err        string
		expectLogs []spiretest.LogEntry
		paramReq   *agentpb.RenewAgentRequest
		ackReq     *agentpb.RenewAgentRequest
		noAgentID  bool
	}{
		{
			name: "success",
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			test := setupServiceTest(t)
			defer test.Cleanup()

			_, err := test.ds.CreateAttestedNode(ctx, &datastore.CreateAttestedNodeRequest{
				Node: defaultNode,
			})
			require.NoError(t, err)

			now := test.ca.Clock().Now().UTC()
			expiredAt := now.Add(test.ca.X509SVIDTTL())

			stream, err := test.client.RenewAgent(ctx)
			require.NoError(t, err)

			err = stream.Send(tt.paramReq)
			require.NoError(t, err)

			resp, err := stream.Recv()
			require.NoError(t, err)
			require.NotNil(t, resp)

			spiretest.AssertProtoEqual(t, agentIDType, resp.Svid.Id)
			require.Equal(t, expiredAt.Unix, resp.Svid.ExpiresAt)

			certChain, err := x509util.RawCertsToCertificates(resp.Svid.CertChain)
			require.NoError(t, err)
			require.NotEmpty(t, certChain)

			x509Svid := certChain[0]
			require.Equal(t, expiredAt, x509Svid.NotAfter.Unix())
			require.Equal(t, []*url.URL{agentID.URL()}, x509Svid.URIs)
			// TODO: verify signature

			node, err := test.ds.FetchAttestedNode(ctx, &datastore.FetchAttestedNodeRequest{
				SpiffeId: agentID.String(),
			})
			require.NoError(t, err)
			node.Node.SpiffeId

			// TODO: verify new values on DS

			err = stream.Send(tt.ackReq)
			require.NoError(t, err)

			// TODO: verify

		})
	}
}

type serviceTest struct {
	ca           *fakeserverca.CA
	client       agentpb.AgentClient
	done         func()
	ds           *fakedatastore.DataStore
	logHook      *test.Hook
	rateLimiter  *fakeRateLimiter
	withCallerID bool
}

func (c *serviceTest) Cleanup() {
	c.done()
}

func setupServiceTest(t *testing.T) *serviceTest {
	ca := fakeserverca.New(t, td.IDString(), &fakeserverca.Options{})
	ds := fakedatastore.New(t)
	service := agent.New(agent.Config{
		Datastore: ds,
	})

	log, logHook := test.NewNullLogger()
	registerFn := func(s *grpc.Server) {
		agent.RegisterService(s, service)
	}
	rateLimiter := &fakeRateLimiter{}

	test := &serviceTest{
		ca:          ca,
		ds:          ds,
		logHook:     logHook,
		rateLimiter: rateLimiter,
	}

	contextFn := func(ctx context.Context) context.Context {
		ctx = rpccontext.WithLogger(ctx, log)
		ctx = rpccontext.WithRateLimiter(ctx, rateLimiter)
		if test.withCallerID {
			ctx = rpccontext.WithCallerID(ctx, agentID)
		}
		return ctx
	}

	conn, done := spiretest.NewAPIServer(t, registerFn, contextFn)
	test.done = done
	test.client = agentpb.NewAgentClient(conn)

	return test
}

type fakeRateLimiter struct {
	count int
	err   error
}

func (f *fakeRateLimiter) RateLimit(ctx context.Context, count int) error {
	if f.count != count {
		return fmt.Errorf("rate limiter got %d but expected %d", count, f.count)
	}

	return f.err
}
