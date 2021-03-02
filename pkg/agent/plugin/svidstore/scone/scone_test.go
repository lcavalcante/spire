package scone

import (
    "context"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "fmt"
    hclog "github.com/hashicorp/go-hclog"
    "github.com/spiffe/spire/pkg/agent/plugin/svidstore"
    "github.com/spiffe/spire/pkg/common/x509util"
    "github.com/spiffe/spire/proto/spire/common"
    spi "github.com/spiffe/spire/proto/spire/common/plugin"
    "github.com/stretchr/testify/require"
    "io/ioutil"
    "math/big"
    "net/http"
    "net/http/httptest"
    "os"
    "path/filepath"
    "testing"
    "time"
)

func TestPutX509SVID(t *testing.T) {
    template := x509.Certificate{
        SerialNumber: big.NewInt(1),
        Subject: pkix.Name{
            Organization: []string{"Acme Co"},
        },
        NotBefore: time.Now(),
        NotAfter:  time.Now().Add(time.Hour * 24 * 180),

        KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
        ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
        BasicConstraintsValid: true,
    }

    // Mock http server
    mocks := httptest.NewServer(
        http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            if r.URL.Path == "/session" {
                w.WriteHeader(http.StatusCreated)
                w.Header().Set("Content-Type", "application/json")
                w.Write([]byte(`{"hash": "1234567890"}`))
            }
        }),
    )

    // Create certificate
    pkey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
    derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(pkey), pkey)
    if err != nil {
        t.Logf("fail to create")
    }
    cert, err := x509.ParseCertificate(derBytes)
    if err != nil {
        t.Logf("fail to parse")
    }
    keyData, err := x509.MarshalPKCS8PrivateKey(pkey)
    if err != nil {
        t.Logf("fail to marshal")
    }
    var certList = []*x509.Certificate{cert}

    var tdir = "predecessor_dir"
    var tcert = "cert.crt"
    var tkey = "key.key"
    dname, err := ioutil.TempDir("", tdir)
    if err != nil {
        panic(err)
    }
    certf := filepath.Join(dname, tcert)
    certOut, err := os.Create(certf)
    if err != nil {
        panic("Failed to open cert.pem for writing")
    }
    if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
        panic(err)
    }
    if err := certOut.Close(); err != nil {
        panic(err)
    }
    keyf := filepath.Join(dname, tkey)
    keyOut, err := os.OpenFile(keyf, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
    if err != nil {
        panic("Failed to open key.pem for writing")
    }
    privBytes, err := x509.MarshalPKCS8PrivateKey(pkey)
    if err != nil {
        panic("Unable to marshal private key")
    }
    if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
        panic("Failed to write data to key.pem")
    }
    if err := keyOut.Close(); err != nil {
        panic("Error closing key.pem")
    }
    defer os.RemoveAll(dname)

    testCases := []struct {
        name        string
        err         string
        SessionName string
        SessionHash string
        config      string
        Svid        *svidstore.X509SVID
    }{
        {
            name: "test base",
            Svid: &svidstore.X509SVID{
                SpiffeId:    "spiffe://acme.com/billing/payments",
                Bundle:      nil,
                X509SvidKey: keyData,
                X509Svid:    x509util.DERFromCertificates(certList),
            },
            SessionName: "t1",
            SessionHash: "h1",
            config:      "cas_predecessor_dir = \"" + dname +"\"\ncas_address = \"" + mocks.URL + "\"\ncas_client_certificate = \"" + certf + "\"\ncas_client_key = \"" + keyf + "\"",
            err:         "scone: errr",
        },
        {
            name: "test empty svid",
            Svid: &svidstore.X509SVID{
                SpiffeId:    "spiffe://acme.com/billing/payments",
                Bundle:      nil,
                X509SvidKey: keyData,
                X509Svid:    nil,
            },
            SessionName: "t2",
            SessionHash: "h2",
            config:      "cas_predecessor_dir = \"/tmp\"\ncas_address = \"" + mocks.URL + "\"\ncas_client_certificate = \"/tmp/client.crt\"\ncas_client_key = \"/tmp/client-key.key\"",
            err:         "scone: errr",
        },
    }
    for _, testCase := range testCases {
        testCase := testCase
        t.Run(testCase.name, func(t *testing.T) {
            p := New()
            ctx := context.Background()
            confres, err := p.Configure(ctx, &spi.ConfigureRequest{
                Configuration: testCase.config,
            })
            appLogger := hclog.New(&hclog.LoggerOptions{
                Name:  "my-app",
                Level: hclog.LevelFromString("DEBUG"),
            })
            p.SetLogger(appLogger)
            if err != nil {
                t.Log(err)
                t.Log(confres)
            }
            var selectors []*common.Selector
            selectors = append(selectors, makeSelector("cas_session_name", testCase.SessionHash))
            selectors = append(selectors, makeSelector("cas_session_hash", testCase.SessionName))
            hashf := filepath.Join(dname, "spire-svid-" + testCase.SessionHash)
            err = ioutil.WriteFile(hashf, []byte{1, 2}, 0666)
            if err != nil {
                panic(err)
            }
            resp, err := p.PutX509SVID(ctx, &svidstore.PutX509SVIDRequest{
                Selectors: selectors,
                Svid:      testCase.Svid,
            })
            if testCase.err != "" {
                require.Nil(t, err)
                return
            }

            require.NoError(t, err)
            require.NotNil(t, resp)
        })
    }
    defer mocks.Close()
}

func makeSelector(kind, value string) *common.Selector {
    return &common.Selector{
        Type:  kind,
        Value: value,
    }
}

func publicKey(priv interface{}) interface{} {
    switch k := priv.(type) {
    case *rsa.PrivateKey:
        return &k.PublicKey
    case *ecdsa.PrivateKey:
        return &k.PublicKey
    default:
        return nil
    }
}

func pemBlockForKey(priv interface{}) *pem.Block {
    switch k := priv.(type) {
    case *rsa.PrivateKey:
        return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
    case *ecdsa.PrivateKey:
        b, err := x509.MarshalECPrivateKey(k)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
            os.Exit(2)
        }
        return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
    default:
        return nil
    }
}
