package api

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"net/url"

	"github.com/spiffe/spire/pkg/common/util"

	"github.com/spiffe/go-spiffe/spiffe"

	"github.com/mitchellh/cli"
	"github.com/spiffe/go-spiffe/proto/spiffe/workload"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
)

func NewValidateX509Command() cli.Command {
	return newValidateX509Command(common_cli.DefaultEnv, newWorkloadClient)
}

func newValidateX509Command(env *common_cli.Env, clientMaker workloadClientMaker) cli.Command {
	return adaptCommand(env, clientMaker, new(validateX509Command))
}

type validateX509Command struct {
	svid string
}

func (*validateX509Command) name() string {
	return "validate X509"
}

func (*validateX509Command) synopsis() string {
	return "Validates a X509 SVID"
}

func (c *validateX509Command) appendFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.svid, "svid", "", "path to X509 SVID")
}

func (c *validateX509Command) run(ctx context.Context, env *common_cli.Env, client *workloadClient) error {
	if len(c.svid) == 0 {
		return errors.New("svid path must be specified")
	}

	// validate provided X509-SVID against bundle
	resp, err := c.validateX509SVID(ctx, client)
	if err != nil {
		return err
	}

	if err := env.Println("X509-SVID is valid."); err != nil {
		return err
	}
	if err := env.Println("SPIFFE ID:", resp[0][0].URIs[0]); err != nil {
		return err
	}

	return nil
}

// validateX509SVID validates provided X509-SVID against fetched bundle
func (c *validateX509Command) validateX509SVID(ctx context.Context, client *workloadClient) ([][]*x509.Certificate, error) {
	// Load certificates from provided X509-SVID
	certs, err := util.LoadCertificates(c.svid)
	if err != nil {
		return nil, err
	}

	// Fetch bundles on x509.CertPool format
	bundles, err := c.fetchBundles(ctx, client)
	if err != nil {
		return nil, err
	}

	// Verify X509-SVID format and if it is signed by fetched bundle
	return spiffe.VerifyPeerCertificate(certs, bundles, spiffe.ExpectAnyPeer())
}

// fetchBundles fetchs bundles from workload api and return a map with bundle and federated bundles
func (c *validateX509Command) fetchBundles(ctx context.Context, client *workloadClient) (map[string]*x509.CertPool, error) {
	// fetch svid to get bundles
	resp, err := c.fetchX509SVID(ctx, client)
	if err != nil {
		return nil, err
	}

	if len(resp.Svids) == 0 {
		return nil, errors.New("no X509-SVID found")
	}

	bundlePools := make(map[string]*x509.CertPool)

	// Add federated bundles
	for id, bundle := range resp.FederatedBundles {
		pool, err := c.createCertPool(bundle)
		if err != nil {
			return nil, err
		}

		bundlePools[id] = pool
	}

	// Get trustdomain
	svid := resp.Svids[0]
	spiffeID, err := url.Parse(svid.SpiffeId)
	if err != nil {
		return nil, err
	}
	trustDomain := spiffe.TrustDomainID(spiffeID.Host)

	// Add SVID bundle
	pool, err := c.createCertPool(svid.Bundle)
	if err != nil {
		return nil, err
	}
	bundlePools[trustDomain] = pool

	return bundlePools, nil
}

// fetchX509SVID fetch X509-SVID from workload api
func (c *validateX509Command) fetchX509SVID(ctx context.Context, client *workloadClient) (*workload.X509SVIDResponse, error) {
	ctx, cancel := client.prepareContext(ctx)
	defer cancel()

	stream, err := client.FetchX509SVID(ctx, &workload.X509SVIDRequest{})
	if err != nil {
		return nil, err
	}

	return stream.Recv()
}

// createCertPool creates a CertPool from bundle in byte format
func (c *validateX509Command) createCertPool(bundle []byte) (*x509.CertPool, error) {
	bundles, err := x509.ParseCertificates(bundle)
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	for _, bundle := range bundles {
		pool.AddCert(bundle)
	}

	return pool, nil
}
