/*
Copyright 2026 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package k8scloudoperator

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sigs.k8s.io/vsphere-csi-driver/v3/pkg/common/certwatcher"
)

// These tests cover the mTLS handshake for the K8sCloudOperator gRPC service
// end to end: a real TLS listener backed by a CertWatcher, and real clients
// dialling it. They exist because the handshake is otherwise very hard to
// exercise - the service listens on 127.0.0.1 only, and its two in-tree
// callers are reached solely via vSAN SNA volume provisioning and disk
// decommission, neither of which runs in a typical cluster.
//
// NOTE: newServerTransportCredentials/newClientTransportCredentials read from
// the package-level DefaultK8sCloudOperatorCertDir, so they cannot be called
// against a temp directory. The helpers below mirror the tls.Config those
// functions build. That means these tests validate the *design* (CertWatcher
// + GetConfigForClient + VerifyConnection composition) but will not catch a
// future divergence in the production builders. Threading a cert directory
// through both functions would let these tests call them directly.

// mtlsCipherSuites matches the suite list pinned in the production builders.
var mtlsCipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_AES_128_GCM_SHA256,
	tls.TLS_AES_256_GCM_SHA384,
}

type testCA struct {
	certPEM []byte
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
}

func newTestCA(t *testing.T, cn string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return &testCA{
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		cert:    cert,
		key:     key,
	}
}

// issue mints a leaf signed by the CA. serverAuth adds the 127.0.0.1 IP SAN
// the server identity carries in the shipped manifests.
func (ca *testCA) issue(t *testing.T, cn string, serverAuth bool,
	notBefore, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	if serverAuth {
		tmpl.DNSNames = []string{"localhost"}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func writeCertDir(t *testing.T, dir string, certPEM, keyPEM, caPEM []byte) (certPath, keyPath, caPath string) {
	t.Helper()
	certPath = filepath.Join(dir, "tls.crt")
	keyPath = filepath.Join(dir, "tls.key")
	caPath = filepath.Join(dir, "ca.crt")
	require.NoError(t, os.WriteFile(certPath, certPEM, 0o600))
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))
	require.NoError(t, os.WriteFile(caPath, caPEM, 0o600))
	return certPath, keyPath, caPath
}

// serverTLSConfigFromWatcher mirrors newServerTransportCredentials: a fresh CA
// pool and cert are fetched per handshake, client certs are required and
// verified, the accepted CommonName is pinned, and session resumption is off
// so every connection re-verifies.
func serverTLSConfigFromWatcher(cw *certwatcher.CertWatcher) (*tls.Config, error) {
	base := func(clientCAs *x509.CertPool) *tls.Config {
		return &tls.Config{
			MinVersion:             tls.VersionTLS12,
			CipherSuites:           mtlsCipherSuites,
			ClientAuth:             tls.RequireAndVerifyClientCert,
			GetCertificate:         cw.GetCertificate,
			ClientCAs:              clientCAs,
			VerifyConnection:       verifyK8sCloudOperatorClientConnection,
			SessionTicketsDisabled: true,
		}
	}
	pool, err := cw.GetCACertPool()
	if err != nil {
		return nil, err
	}
	cfg := base(pool)
	cfg.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		fresh, err := cw.GetCACertPool()
		if err != nil {
			return nil, err
		}
		return base(fresh), nil
	}
	return cfg, nil
}

// serverAcceptedByte is written by the test server once a handshake - client
// certificate verification and CN pinning included - has fully succeeded.
const serverAcceptedByte = byte('K')

// startTLSServer runs a TLS listener that completes the handshake and then
// writes serverAcceptedByte.
//
// The write matters. Under TLS 1.3 the client's Handshake() returns before the
// server has processed the client's Certificate message, so a server-side
// rejection (bad CA, unexpected CommonName, expired client cert) does NOT
// surface as a tls.Dial error - it arrives afterwards as an alert on first
// read. Requiring a byte back is what turns "the server accepted us" into
// something the client can actually assert on. In production this is why an
// unauthorised caller sees the RPC fail rather than the dial.
func startTLSServer(t *testing.T, cfg *tls.Config) net.Listener {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				tc, ok := c.(*tls.Conn)
				if !ok {
					return
				}
				_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
				if err := tc.HandshakeContext(context.Background()); err != nil {
					return
				}
				_, _ = tc.Write([]byte{serverAcceptedByte})
			}(conn)
		}
	}()
	return ln
}

// dialWith completes a client handshake AND confirms the server accepted the
// connection, returning the server's leaf. See startTLSServer for why the
// read-back is required rather than relying on the dial error alone.
func dialWith(t *testing.T, addr string, clientCertPEM, clientKeyPEM, caPEM []byte) (*x509.Certificate, error) {
	t.Helper()
	cert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(caPEM))

	conn, err := tls.Dial("tcp", addr, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		CipherSuites: mtlsCipherSuites,
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	peers := conn.ConnectionState().PeerCertificates
	require.NotEmpty(t, peers)

	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return nil, err
	}
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err != nil {
		// Server-side rejection surfaces here as a TLS alert.
		return nil, err
	}
	if buf[0] != serverAcceptedByte {
		return nil, errUnexpectedServerReply
	}
	return peers[0], nil
}

var errUnexpectedServerReply = errorString("server did not confirm the connection was accepted")

type errorString string

func (e errorString) Error() string { return string(e) }

// TestMTLS_HandshakeSucceedsWithPinnedClientCN is the positive control: the
// authorised client identity completes a handshake.
func TestMTLS_HandshakeSucceedsWithPinnedClientCN(t *testing.T) {
	ca := newTestCA(t, "test-ca")
	now := time.Now()
	srvCert, srvKey := ca.issue(t, "vmware-system-csi-k8scloudoperator-server", true,
		now.Add(-time.Hour), now.Add(time.Hour))
	cliCert, cliKey := ca.issue(t, k8sCloudOperatorClientCertCN, false,
		now.Add(-time.Hour), now.Add(time.Hour))

	certPath, keyPath, caPath := writeCertDir(t, t.TempDir(), srvCert, srvKey, ca.certPEM)
	cw, err := certwatcher.New(certPath, keyPath, caPath)
	require.NoError(t, err)

	cfg, err := serverTLSConfigFromWatcher(cw)
	require.NoError(t, err)
	ln := startTLSServer(t, cfg)

	peer, err := dialWith(t, ln.Addr().String(), cliCert, cliKey, ca.certPEM)
	require.NoError(t, err, "authorised client should complete the mTLS handshake")
	require.Equal(t, "vmware-system-csi-k8scloudoperator-server", peer.Subject.CommonName)
}

// TestMTLS_RejectsWrongClientCN covers the CN pinning: a certificate that
// chains correctly to the trusted CA but carries a different CommonName must
// still be refused.
func TestMTLS_RejectsWrongClientCN(t *testing.T) {
	ca := newTestCA(t, "test-ca")
	now := time.Now()
	srvCert, srvKey := ca.issue(t, "vmware-system-csi-k8scloudoperator-server", true,
		now.Add(-time.Hour), now.Add(time.Hour))
	// Same CA, wrong identity.
	cliCert, cliKey := ca.issue(t, "some-other-workload", false,
		now.Add(-time.Hour), now.Add(time.Hour))

	certPath, keyPath, caPath := writeCertDir(t, t.TempDir(), srvCert, srvKey, ca.certPEM)
	cw, err := certwatcher.New(certPath, keyPath, caPath)
	require.NoError(t, err)

	cfg, err := serverTLSConfigFromWatcher(cw)
	require.NoError(t, err)
	ln := startTLSServer(t, cfg)

	_, err = dialWith(t, ln.Addr().String(), cliCert, cliKey, ca.certPEM)
	require.Error(t, err, "a CA-signed cert with an unexpected CommonName must be rejected")
}

// TestMTLS_RejectsClientSignedByForeignCA covers a client whose cert does not
// chain to the trusted CA at all, even though its CommonName is correct.
func TestMTLS_RejectsClientSignedByForeignCA(t *testing.T) {
	ca := newTestCA(t, "test-ca")
	foreign := newTestCA(t, "foreign-ca")
	now := time.Now()
	srvCert, srvKey := ca.issue(t, "vmware-system-csi-k8scloudoperator-server", true,
		now.Add(-time.Hour), now.Add(time.Hour))
	cliCert, cliKey := foreign.issue(t, k8sCloudOperatorClientCertCN, false,
		now.Add(-time.Hour), now.Add(time.Hour))

	certPath, keyPath, caPath := writeCertDir(t, t.TempDir(), srvCert, srvKey, ca.certPEM)
	cw, err := certwatcher.New(certPath, keyPath, caPath)
	require.NoError(t, err)

	cfg, err := serverTLSConfigFromWatcher(cw)
	require.NoError(t, err)
	ln := startTLSServer(t, cfg)

	_, err = dialWith(t, ln.Addr().String(), cliCert, cliKey, ca.certPEM)
	require.Error(t, err, "client cert from an untrusted CA must be rejected")
}

// TestMTLS_ServerCertRotationTakesEffectOnNextHandshake is the end-to-end
// rotation proof: after the server's leaf is replaced on disk, a subsequent
// handshake presents the NEW certificate without a restart. This is what the
// GetCertificate hook plus the CertWatcher exist to deliver.
func TestMTLS_ServerCertRotationTakesEffectOnNextHandshake(t *testing.T) {
	ca := newTestCA(t, "test-ca")
	now := time.Now()
	srvCert1, srvKey1 := ca.issue(t, "vmware-system-csi-k8scloudoperator-server", true,
		now.Add(-time.Hour), now.Add(time.Hour))
	cliCert, cliKey := ca.issue(t, k8sCloudOperatorClientCertCN, false,
		now.Add(-time.Hour), now.Add(time.Hour))

	dir := t.TempDir()
	certPath, keyPath, caPath := writeCertDir(t, dir, srvCert1, srvKey1, ca.certPEM)
	cw, err := certwatcher.New(certPath, keyPath, caPath)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = cw.Start(ctx) }()
	time.Sleep(200 * time.Millisecond)

	cfg, err := serverTLSConfigFromWatcher(cw)
	require.NoError(t, err)
	ln := startTLSServer(t, cfg)

	peer1, err := dialWith(t, ln.Addr().String(), cliCert, cliKey, ca.certPEM)
	require.NoError(t, err)

	// Rotate the server leaf, same CA so the client still trusts it.
	srvCert2, srvKey2 := ca.issue(t, "vmware-system-csi-k8scloudoperator-server", true,
		now.Add(-time.Hour), now.Add(2*time.Hour))
	require.NoError(t, os.WriteFile(certPath, srvCert2, 0o600))
	require.NoError(t, os.WriteFile(keyPath, srvKey2, 0o600))

	require.Eventually(t, func() bool {
		peer2, err := dialWith(t, ln.Addr().String(), cliCert, cliKey, ca.certPEM)
		return err == nil && peer2.SerialNumber.Cmp(peer1.SerialNumber) != 0
	}, 10*time.Second, 200*time.Millisecond,
		"server kept presenting the pre-rotation certificate")
}

// TestMTLS_NewClientCAIsHonouredWithoutRestart covers the CA-rotation half of
// the design. GetConfigForClient re-fetches the CA pool per handshake, so a
// client issued by a newly-trusted CA should be accepted without a restart -
// and, critically, a client from the CA that is no longer trusted must then be
// refused.
func TestMTLS_NewClientCAIsHonouredWithoutRestart(t *testing.T) {
	caOld := newTestCA(t, "test-ca-old")
	caNew := newTestCA(t, "test-ca-new")
	now := time.Now()

	// Server identity stays issued by caOld for its own leaf; only the
	// trusted client CA bundle rotates.
	srvCert, srvKey := caOld.issue(t, "vmware-system-csi-k8scloudoperator-server", true,
		now.Add(-time.Hour), now.Add(time.Hour))
	cliOld, cliOldKey := caOld.issue(t, k8sCloudOperatorClientCertCN, false,
		now.Add(-time.Hour), now.Add(time.Hour))
	cliNew, cliNewKey := caNew.issue(t, k8sCloudOperatorClientCertCN, false,
		now.Add(-time.Hour), now.Add(time.Hour))

	dir := t.TempDir()
	certPath, keyPath, caPath := writeCertDir(t, dir, srvCert, srvKey, caOld.certPEM)
	cw, err := certwatcher.New(certPath, keyPath, caPath)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = cw.Start(ctx) }()
	time.Sleep(200 * time.Millisecond)

	cfg, err := serverTLSConfigFromWatcher(cw)
	require.NoError(t, err)
	ln := startTLSServer(t, cfg)

	// Baseline: the old client identity works.
	_, err = dialWith(t, ln.Addr().String(), cliOld, cliOldKey, caOld.certPEM)
	require.NoError(t, err)

	// A client from the not-yet-trusted CA is refused.
	_, err = dialWith(t, ln.Addr().String(), cliNew, cliNewKey, caOld.certPEM)
	require.Error(t, err, "client from an untrusted CA should be refused before rotation")

	// Rotate the trusted CA bundle. Writing tls.crt as well reproduces
	// cert-manager rewriting the whole Secret, which is what the watcher
	// relies on to notice a ca.crt change.
	require.NoError(t, os.WriteFile(caPath, caNew.certPEM, 0o600))
	require.NoError(t, os.WriteFile(certPath, srvCert, 0o600))
	require.NoError(t, os.WriteFile(keyPath, srvKey, 0o600))

	require.Eventually(t, func() bool {
		_, err := dialWith(t, ln.Addr().String(), cliNew, cliNewKey, caOld.certPEM)
		return err == nil
	}, 10*time.Second, 200*time.Millisecond,
		"new client CA was not honoured without a restart")

	// The old client identity must now be rejected: the pool was replaced,
	// not appended to.
	_, err = dialWith(t, ln.Addr().String(), cliOld, cliOldKey, caOld.certPEM)
	require.Error(t, err, "client from the retired CA should no longer be accepted")
}

// TestMTLS_ExpiredServerCertIsRejectedByClient confirms an expired server leaf
// fails the handshake at the client. The watcher itself does no validity
// checking, so this is where expiry actually surfaces.
func TestMTLS_ExpiredServerCertIsRejectedByClient(t *testing.T) {
	ca := newTestCA(t, "test-ca")
	now := time.Now()
	srvCert, srvKey := ca.issue(t, "vmware-system-csi-k8scloudoperator-server", true,
		now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	cliCert, cliKey := ca.issue(t, k8sCloudOperatorClientCertCN, false,
		now.Add(-time.Hour), now.Add(time.Hour))

	certPath, keyPath, caPath := writeCertDir(t, t.TempDir(), srvCert, srvKey, ca.certPEM)
	cw, err := certwatcher.New(certPath, keyPath, caPath)
	require.NoError(t, err, "certwatcher loads an expired cert without complaint")

	cfg, err := serverTLSConfigFromWatcher(cw)
	require.NoError(t, err)
	ln := startTLSServer(t, cfg)

	_, err = dialWith(t, ln.Addr().String(), cliCert, cliKey, ca.certPEM)
	require.Error(t, err, "client must reject an expired server certificate")
}

// TestMTLS_ExpiredClientCertIsRejectedByServer is the mirror case.
func TestMTLS_ExpiredClientCertIsRejectedByServer(t *testing.T) {
	ca := newTestCA(t, "test-ca")
	now := time.Now()
	srvCert, srvKey := ca.issue(t, "vmware-system-csi-k8scloudoperator-server", true,
		now.Add(-time.Hour), now.Add(time.Hour))
	cliCert, cliKey := ca.issue(t, k8sCloudOperatorClientCertCN, false,
		now.Add(-48*time.Hour), now.Add(-24*time.Hour))

	certPath, keyPath, caPath := writeCertDir(t, t.TempDir(), srvCert, srvKey, ca.certPEM)
	cw, err := certwatcher.New(certPath, keyPath, caPath)
	require.NoError(t, err)

	cfg, err := serverTLSConfigFromWatcher(cw)
	require.NoError(t, err)
	ln := startTLSServer(t, cfg)

	_, err = dialWith(t, ln.Addr().String(), cliCert, cliKey, ca.certPEM)
	require.Error(t, err, "server must reject an expired client certificate")
}

// TestMTLS_RejectsTLS11AndUnlistedCiphers covers the negative protocol cases:
// MinVersion and the pinned cipher list must both be enforced.
func TestMTLS_RejectsTLS11AndUnlistedCiphers(t *testing.T) {
	ca := newTestCA(t, "test-ca")
	now := time.Now()
	srvCert, srvKey := ca.issue(t, "vmware-system-csi-k8scloudoperator-server", true,
		now.Add(-time.Hour), now.Add(time.Hour))
	cliCert, cliKey := ca.issue(t, k8sCloudOperatorClientCertCN, false,
		now.Add(-time.Hour), now.Add(time.Hour))

	certPath, keyPath, caPath := writeCertDir(t, t.TempDir(), srvCert, srvKey, ca.certPEM)
	cw, err := certwatcher.New(certPath, keyPath, caPath)
	require.NoError(t, err)

	cfg, err := serverTLSConfigFromWatcher(cw)
	require.NoError(t, err)
	ln := startTLSServer(t, cfg)

	clientKeyPair, err := tls.X509KeyPair(cliCert, cliKey)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(ca.certPEM))

	t.Run("TLS 1.1 is refused", func(t *testing.T) {
		conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
			MinVersion:   tls.VersionTLS11,
			MaxVersion:   tls.VersionTLS11,
			Certificates: []tls.Certificate{clientKeyPair},
			RootCAs:      pool,
		})
		if err == nil {
			_ = conn.Close()
		}
		require.Error(t, err, "TLS 1.1 must be refused")
	})

	t.Run("unlisted CBC cipher is refused", func(t *testing.T) {
		conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS12,
			CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA},
			Certificates: []tls.Certificate{clientKeyPair},
			RootCAs:      pool,
		})
		if err == nil {
			_ = conn.Close()
		}
		require.Error(t, err, "a cipher outside the pinned list must be refused")
	})
}

// TestMTLS_PlaintextDialIsRefused confirms an unencrypted client cannot use
// the service, which is the regression the TLS enablement is guarding.
func TestMTLS_PlaintextDialIsRefused(t *testing.T) {
	ca := newTestCA(t, "test-ca")
	now := time.Now()
	srvCert, srvKey := ca.issue(t, "vmware-system-csi-k8scloudoperator-server", true,
		now.Add(-time.Hour), now.Add(time.Hour))

	certPath, keyPath, caPath := writeCertDir(t, t.TempDir(), srvCert, srvKey, ca.certPEM)
	cw, err := certwatcher.New(certPath, keyPath, caPath)
	require.NoError(t, err)

	cfg, err := serverTLSConfigFromWatcher(cw)
	require.NoError(t, err)
	ln := startTLSServer(t, cfg)

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	require.NoError(t, err, "TCP connect itself should succeed")
	defer conn.Close()

	// Send bytes that are not a TLS ClientHello and expect no usable reply.
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"))
	require.NoError(t, err)

	buf := make([]byte, 64)
	n, readErr := conn.Read(buf)
	// A TLS listener answers a non-TLS hello with an alert or just closes;
	// either way the plaintext client gets nothing it can use.
	if readErr == nil {
		require.NotContains(t, string(buf[:n]), "HTTP",
			"plaintext client must not get an application-level response")
	}
}
