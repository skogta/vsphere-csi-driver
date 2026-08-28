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

package certwatcher

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// writeIdentityKubeletStyle reproduces how the kubelet actually materialises a
// Secret volume, which is NOT a plain file write: contents live in a
// timestamped directory, a "..data" symlink points at it, and each key is a
// symlink into "..data". Updates create a fresh timestamped directory and
// atomically swap the "..data" symlink, then delete the old directory.
//
// This matters because the watcher adds inotify watches on tls.crt/tls.key,
// which resolve through those symlinks to an inode that a rotation deletes.
// Observed on a live supervisor:
//
//	..data -> ..2026_08_28_06_34_35.2696836701
//	tls.crt -> ..data/tls.crt
func writeIdentityKubeletStyle(t *testing.T, dir, stamp string,
	certPEM, keyPEM, caPEM []byte) (certPath, keyPath, caPath string) {
	t.Helper()

	dataDir := filepath.Join(dir, ".."+stamp)
	require.NoError(t, os.MkdirAll(dataDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "tls.crt"), certPEM, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "tls.key"), keyPEM, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "ca.crt"), caPEM, 0o600))

	// Atomically swap the ..data symlink via rename, as the kubelet does.
	dataLink := filepath.Join(dir, "..data")
	tmpLink := filepath.Join(dir, "..data_tmp")
	_ = os.Remove(tmpLink)
	require.NoError(t, os.Symlink(".."+stamp, tmpLink))

	oldTarget, hadOld := "", false
	if target, err := os.Readlink(dataLink); err == nil {
		oldTarget, hadOld = target, true
	}
	require.NoError(t, os.Rename(tmpLink, dataLink))

	certPath = filepath.Join(dir, "tls.crt")
	keyPath = filepath.Join(dir, "tls.key")
	caPath = filepath.Join(dir, "ca.crt")
	for _, p := range []string{certPath, keyPath, caPath} {
		if _, err := os.Lstat(p); os.IsNotExist(err) {
			require.NoError(t, os.Symlink(filepath.Join("..data", filepath.Base(p)), p))
		}
	}

	// The kubelet removes the previous timestamped directory after the swap,
	// which is what destroys the inode the watcher was watching.
	if hadOld && oldTarget != ".."+stamp {
		require.NoError(t, os.RemoveAll(filepath.Join(dir, oldTarget)))
	}

	return certPath, keyPath, caPath
}

// generateLeafWithValidity is generateLeaf with caller-controlled validity and
// serial, so tests can mint already-expired or not-yet-valid certificates.
func generateLeafWithValidity(t *testing.T, commonName string, serial int64,
	notBefore, notAfter time.Time, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	require.NoError(t, err)

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// currentLeafCN returns the CommonName of the leaf the watcher is serving.
func currentLeafCN(cw *CertWatcher) (string, error) {
	cert, err := cw.GetCertificate(nil)
	if err != nil {
		return "", err
	}
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return "", err
	}
	return parsed.Subject.CommonName, nil
}

func startWatcher(t *testing.T, cw *CertWatcher) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = cw.Start(ctx) }()
	// Give the watch goroutine a moment to install its watches before the
	// test mutates the directory, so we test rotation and not a startup race.
	time.Sleep(200 * time.Millisecond)
}

// TestCertWatcher_KubeletSymlinkSwapRotation is the rotation test that matches
// production: the leaf is replaced by a kubelet-style atomic directory swap
// rather than an in-place file write.
func TestCertWatcher_KubeletSymlinkSwapRotation(t *testing.T) {
	caPEM, caKey, caCert := generateCA(t, "test-ca")
	cert1, key1 := generateLeaf(t, "leaf-gen-1", caCert, caKey)

	dir := t.TempDir()
	certPath, keyPath, caPath := writeIdentityKubeletStyle(t, dir, "2026_01_01_00_00_00.1", cert1, key1, caPEM)

	cw, err := New(certPath, keyPath, caPath)
	require.NoError(t, err)
	startWatcher(t, cw)

	cn, err := currentLeafCN(cw)
	require.NoError(t, err)
	require.Equal(t, "leaf-gen-1", cn)

	cert2, key2 := generateLeaf(t, "leaf-gen-2", caCert, caKey)
	writeIdentityKubeletStyle(t, dir, "2026_01_01_00_05_00.2", cert2, key2, caPEM)

	require.Eventually(t, func() bool {
		cn, err := currentLeafCN(cw)
		return err == nil && cn == "leaf-gen-2"
	}, 10*time.Second, 100*time.Millisecond,
		"watcher did not pick up a kubelet-style symlink-swap rotation")
}

// TestCertWatcher_SurvivesRepeatedSymlinkSwaps guards the watch surviving many
// rotations. Each swap deletes the inode the watch was attached to, so a
// re-watch that silently fails would show up as a stall after the first
// generation. A live supervisor soak saw 18 consecutive rotations reload
// cleanly; this covers the same property in a unit test.
func TestCertWatcher_SurvivesRepeatedSymlinkSwaps(t *testing.T) {
	caPEM, caKey, caCert := generateCA(t, "test-ca")
	cert1, key1 := generateLeaf(t, "leaf-round-0", caCert, caKey)

	dir := t.TempDir()
	certPath, keyPath, caPath := writeIdentityKubeletStyle(t, dir, "2026_01_01_00_00_00.0", cert1, key1, caPEM)

	cw, err := New(certPath, keyPath, caPath)
	require.NoError(t, err)
	startWatcher(t, cw)

	for i := 1; i <= 6; i++ {
		wantCN := fmt.Sprintf("leaf-round-%d", i)
		certPEM, keyPEM := generateLeaf(t, wantCN, caCert, caKey)
		writeIdentityKubeletStyle(t, dir, fmt.Sprintf("2026_01_01_00_0%d_00.%d", i, i), certPEM, keyPEM, caPEM)

		require.Eventually(t, func() bool {
			cn, err := currentLeafCN(cw)
			return err == nil && cn == wantCN
		}, 10*time.Second, 100*time.Millisecond,
			"watcher stalled at rotation round %d - watch likely not re-established", i)
	}
}

// TestCertWatcher_CAOnlyRotation covers CA rotation arriving without any
// cert/key change. New() deliberately does not watch caPath, relying on
// cert-manager rewriting ca.crt in the same Secret update as the leaf. Under
// kubelet semantics this still works, because the directory swap invalidates
// the leaf watches whether or not the leaf bytes changed - see
// TestCertWatcher_InPlaceCAWriteIsNotObserved for where that stops holding.
func TestCertWatcher_CAOnlyRotation(t *testing.T) {
	caPEM1, caKey1, caCert1 := generateCA(t, "test-ca-1")
	cert1, key1 := generateLeaf(t, "leaf-1", caCert1, caKey1)

	dir := t.TempDir()
	certPath, keyPath, caPath := writeIdentityKubeletStyle(t, dir, "2026_01_01_00_00_00.1", cert1, key1, caPEM1)

	cw, err := New(certPath, keyPath, caPath)
	require.NoError(t, err)
	startWatcher(t, cw)

	poolBefore, err := cw.GetCACertPool()
	require.NoError(t, err)
	require.NotNil(t, poolBefore)

	// Rotate ONLY the CA bundle; leaf and key are byte-identical.
	caPEM2, _, _ := generateCA(t, "test-ca-2")
	writeIdentityKubeletStyle(t, dir, "2026_01_01_00_05_00.2", cert1, key1, caPEM2)

	// Assert on observable behaviour: whether the new CA is trusted.
	newCACert := parseFirstCert(t, caPEM2)
	require.Eventually(t, func() bool {
		pool, err := cw.GetCACertPool()
		if err != nil {
			return false
		}
		return poolTrusts(pool, newCACert)
	}, 10*time.Second, 100*time.Millisecond,
		"CA-only rotation was not observed; watcher is serving a stale CA pool")
}

// TestCertWatcher_CorruptPEMKeepsLastGoodCert asserts a failed reload does not
// destroy the currently-serving identity. A truncated write mid-rotation must
// leave the previous certificate in place rather than nil it out, otherwise
// GetCertificate starts failing every handshake.
func TestCertWatcher_CorruptPEMKeepsLastGoodCert(t *testing.T) {
	caPEM, caKey, caCert := generateCA(t, "test-ca")
	cert1, key1 := generateLeaf(t, "leaf-good", caCert, caKey)

	dir := t.TempDir()
	certPath, keyPath, caPath := writeIdentityKubeletStyle(t, dir, "2026_01_01_00_00_00.1", cert1, key1, caPEM)

	cw, err := New(certPath, keyPath, caPath)
	require.NoError(t, err)
	startWatcher(t, cw)

	// Truncated PEM: parses as neither a cert nor a key.
	writeIdentityKubeletStyle(t, dir, "2026_01_01_00_05_00.2",
		[]byte("-----BEGIN CERTIFICATE-----\ndGhpcyBpcyBub3QgYSBjZXJ0\n"), key1, caPEM)

	// Give the watcher time to observe the bad write and fail its reload.
	time.Sleep(1 * time.Second)

	cn, err := currentLeafCN(cw)
	require.NoError(t, err, "watcher dropped its certificate after a failed reload")
	require.Equal(t, "leaf-good", cn, "watcher should keep serving the last-good certificate")

	pool, err := cw.GetCACertPool()
	require.NoError(t, err)
	require.NotNil(t, pool)
}

// TestCertWatcher_ServesExpiredCertificate documents that the watcher performs
// no validity checking: an expired leaf on disk is loaded and served, and the
// handshake failure surfaces at the peer instead. Worth knowing when triaging,
// since there is no local signal that the served cert is unusable.
func TestCertWatcher_ServesExpiredCertificate(t *testing.T) {
	caPEM, caKey, caCert := generateCA(t, "test-ca")
	expiredCert, expiredKey := generateLeafWithValidity(t, "leaf-expired", 42,
		time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour), caCert, caKey)

	dir := t.TempDir()
	certPath, keyPath, caPath := writeIdentityKubeletStyle(t, dir, "2026_01_01_00_00_00.1",
		expiredCert, expiredKey, caPEM)

	cw, err := New(certPath, keyPath, caPath)
	require.NoError(t, err, "New() does not reject an expired certificate")

	cert, err := cw.GetCertificate(nil)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	require.True(t, parsed.NotAfter.Before(time.Now()),
		"expected the served certificate to be expired")
}

// TestCertWatcher_ConcurrentAccessDuringRotation exercises the RWMutex under
// -race: many readers calling GetCertificate/GetCACertPool while rotations
// drive reload() concurrently.
func TestCertWatcher_ConcurrentAccessDuringRotation(t *testing.T) {
	caPEM, caKey, caCert := generateCA(t, "test-ca")
	cert1, key1 := generateLeaf(t, "leaf-0", caCert, caKey)

	dir := t.TempDir()
	certPath, keyPath, caPath := writeIdentityKubeletStyle(t, dir, "2026_01_01_00_00_00.0", cert1, key1, caPEM)

	cw, err := New(certPath, keyPath, caPath)
	require.NoError(t, err)
	startWatcher(t, cw)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					if _, err := cw.GetCertificate(nil); err != nil {
						t.Errorf("GetCertificate failed during rotation: %v", err)
						return
					}
					if _, err := cw.GetCACertPool(); err != nil {
						t.Errorf("GetCACertPool failed during rotation: %v", err)
						return
					}
				}
			}
		}()
	}

	for i := 1; i <= 5; i++ {
		certPEM, keyPEM := generateLeaf(t, fmt.Sprintf("leaf-%d", i), caCert, caKey)
		writeIdentityKubeletStyle(t, dir, fmt.Sprintf("2026_01_01_00_0%d_00.%d", i, i), certPEM, keyPEM, caPEM)
		time.Sleep(300 * time.Millisecond)
	}

	close(stop)
	wg.Wait()
}

// TestCertWatcher_InPlaceCAWriteIsNotObserved pins the boundary of the
// "we don't need to watch caPath" decision. TestCertWatcher_CAOnlyRotation
// passes only because a kubelet directory swap destroys the inodes behind
// tls.crt/tls.key and so fires events regardless of whether the leaf bytes
// changed. An in-place rewrite of ca.crt alone touches nothing that is
// watched, so it goes unnoticed until the next leaf rotation.
//
// This is currently benign - cert-manager only rewrites ca.crt as part of a
// whole-Secret update - but it is an assumption about an external component,
// so assert it explicitly rather than leaving it implicit.
func TestCertWatcher_InPlaceCAWriteIsNotObserved(t *testing.T) {
	caPEM1, caKey1, caCert1 := generateCA(t, "test-ca-1")
	cert1, key1 := generateLeaf(t, "leaf-1", caCert1, caKey1)

	dir := t.TempDir()
	certPath, keyPath, caPath := writeIdentity(t, dir, cert1, key1, caPEM1)

	cw, err := New(certPath, keyPath, caPath)
	require.NoError(t, err)
	startWatcher(t, cw)

	// Rewrite only ca.crt in place. caPath is not watched, and neither
	// tls.crt nor tls.key is touched.
	caPEM2, _, _ := generateCA(t, "test-ca-2")
	require.NoError(t, os.WriteFile(caPath, caPEM2, 0o600))
	time.Sleep(1 * time.Second)

	newCACert := parseFirstCert(t, caPEM2)
	pool, err := cw.GetCACertPool()
	require.NoError(t, err)
	require.False(t, poolTrusts(pool, newCACert),
		"in-place ca.crt write was observed; certwatcher.New now watches caPath, "+
			"so this test and the comment in New() should be updated")

	// A subsequent leaf rotation re-reads all three files and recovers.
	cert2, key2 := generateLeaf(t, "leaf-2", caCert1, caKey1)
	require.NoError(t, os.WriteFile(certPath, cert2, 0o600))
	require.NoError(t, os.WriteFile(keyPath, key2, 0o600))

	require.Eventually(t, func() bool {
		pool, err := cw.GetCACertPool()
		return err == nil && poolTrusts(pool, newCACert)
	}, 10*time.Second, 100*time.Millisecond,
		"expected a later leaf rotation to pick up the previously-missed CA change")
}

func parseFirstCert(t *testing.T, pemBytes []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert
}

// poolTrusts reports whether pool accepts a leaf signed by caCert, which is
// the property that actually matters for mTLS verification.
func poolTrusts(pool *x509.CertPool, caCert *x509.Certificate) bool {
	_, err := caCert.Verify(x509.VerifyOptions{Roots: pool})
	return err == nil
}
