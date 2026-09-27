//go:build !windows

package winapi

// NewCertStore returns an API that reports the operating system as unsupported.
func NewCertStore() CertStoreAPI { return unsupportedStores{} }

type unsupportedStores struct{}

func (unsupportedStores) Native() bool { return false }

func (unsupportedStores) CertStore(StoreLocation, string) ([]StoreCert, int, error) {
	return nil, 0, ErrUnsupported
}
