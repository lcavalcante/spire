// Provides interfaces and adapters for the IdentityExchanger service
//
// Generated code. Do not modify by hand.
package identityexchanger

import (
	"context"

	"github.com/spiffe/spire/pkg/common/catalog"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	indentityexchanger "github.com/spiffe/spire/proto/spire/server/identityexchanger"
	"google.golang.org/grpc"
)

type ExchangeData = indentityexchanger.ExchangeData                                                 //nolint: golint
type ExchangeRequest = indentityexchanger.ExchangeRequest                                           //nolint: golint
type ExchangeRequest_Data = indentityexchanger.ExchangeRequest_Data                                 //nolint: golint
type ExchangeRequest_Response = indentityexchanger.ExchangeRequest_Response                         //nolint: golint
type ExchangeResponse = indentityexchanger.ExchangeResponse                                         //nolint: golint
type ExchangeResponse_Challenge = indentityexchanger.ExchangeResponse_Challenge                     //nolint: golint
type ExchangeResponse_Response = indentityexchanger.ExchangeResponse_Response                       //nolint: golint
type ExchangeResponse_Response_ = indentityexchanger.ExchangeResponse_Response_                     //nolint: golint
type IdentityExchangerClient = indentityexchanger.IdentityExchangerClient                           //nolint: golint
type IdentityExchangerServer = indentityexchanger.IdentityExchangerServer                           //nolint: golint
type IdentityExchanger_ExchangeClient = indentityexchanger.IdentityExchanger_ExchangeClient         //nolint: golint
type IdentityExchanger_ExchangeServer = indentityexchanger.IdentityExchanger_ExchangeServer         //nolint: golint
type UnimplementedIdentityExchangerServer = indentityexchanger.UnimplementedIdentityExchangerServer //nolint: golint

const (
	Type = "IdentityExchanger"
)

// IdentityExchanger is the client interface for the service type IdentityExchanger interface.
type IdentityExchanger interface {
	Exchange(context.Context) (IdentityExchanger_ExchangeClient, error)
}

// Plugin is the client interface for the service with the plugin related methods used by the catalog to initialize the plugin.
type Plugin interface {
	Configure(context.Context, *spi.ConfigureRequest) (*spi.ConfigureResponse, error)
	Exchange(context.Context) (IdentityExchanger_ExchangeClient, error)
	GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error)
}

// PluginServer returns a catalog PluginServer implementation for the IdentityExchanger plugin.
func PluginServer(server IdentityExchangerServer) catalog.PluginServer {
	return &pluginServer{
		server: server,
	}
}

type pluginServer struct {
	server IdentityExchangerServer
}

func (s pluginServer) PluginType() string {
	return Type
}

func (s pluginServer) PluginClient() catalog.PluginClient {
	return PluginClient
}

func (s pluginServer) RegisterPluginServer(server *grpc.Server) interface{} {
	indentityexchanger.RegisterIdentityExchangerServer(server, s.server)
	return s.server
}

// PluginClient is a catalog PluginClient implementation for the IdentityExchanger plugin.
var PluginClient catalog.PluginClient = pluginClient{}

type pluginClient struct{}

func (pluginClient) PluginType() string {
	return Type
}

func (pluginClient) NewPluginClient(conn *grpc.ClientConn) interface{} {
	return AdaptPluginClient(indentityexchanger.NewIdentityExchangerClient(conn))
}

func AdaptPluginClient(client IdentityExchangerClient) IdentityExchanger {
	return pluginClientAdapter{client: client}
}

type pluginClientAdapter struct {
	client IdentityExchangerClient
}

func (a pluginClientAdapter) Configure(ctx context.Context, in *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	return a.client.Configure(ctx, in)
}

func (a pluginClientAdapter) Exchange(ctx context.Context) (IdentityExchanger_ExchangeClient, error) {
	return a.client.Exchange(ctx)
}

func (a pluginClientAdapter) GetPluginInfo(ctx context.Context, in *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return a.client.GetPluginInfo(ctx, in)
}
