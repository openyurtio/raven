package factory

import (
	"crypto/tls"
	"testing"

	certificatesv1 "k8s.io/api/certificates/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/util/certificate"
)

type fakeFileStore struct{}

func (fakeFileStore) Current() (*tls.Certificate, error) {
	noCertKeyErr := certificate.NoCertKeyError("NO_VALID_CERT")
	return nil, &noCertKeyErr
}

func (fakeFileStore) Update(_ []byte, _ []byte) (*tls.Certificate, error) {
	return nil, nil
}

func (fakeFileStore) CurrentPath() string {
	return ""
}

func fakeClientsetFn(_ *tls.Certificate) (kubernetes.Interface, error) {
	return fake.NewSimpleClientset(), nil
}

func baseConfig(certDir string) *CertManagerConfig {
	return &CertManagerConfig{
		ComponentName: "raven-test",
		CommonName:    "system:node:raven-test",
		CertDir:       certDir,
		Organizations: []string{"system:nodes"},
		SignerName:    certificatesv1.KubeAPIServerClientSignerName,
	}
}

func TestFactoryNewWithNilFileStore(t *testing.T) {
	f := NewCertManagerFactoryWithFnAndStore(fakeClientsetFn, nil)
	manager, err := f.New(baseConfig(t.TempDir()))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if manager == nil {
		t.Fatal("expected manager, got nil")
	}
}

func TestFactoryNewWithInjectedFileStore(t *testing.T) {
	f := NewCertManagerFactoryWithFnAndStore(fakeClientsetFn, fakeFileStore{})
	manager, err := f.New(baseConfig("invalid\x00certdir"))
	if err != nil {
		t.Fatalf("expected no error with injected store, got %v", err)
	}
	if manager == nil {
		t.Fatal("expected manager, got nil")
	}
}
