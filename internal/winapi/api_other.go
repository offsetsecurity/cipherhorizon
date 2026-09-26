//go:build !windows

package winapi

// New returns an API that reports the operating system as unsupported. The
// sensor never registers itself as detected off Windows, so this is only reached by
// a direct caller.
func New() API { return unsupported{} }

type unsupported struct{}

func (unsupported) Native() bool { return false }

func (unsupported) Algorithms(uint32) ([]Algorithm, int, error)       { return nil, 0, ErrUnsupported }
func (unsupported) AlgorithmProviders(string) ([]string, int, error)  { return nil, 0, ErrUnsupported }
func (unsupported) RegisteredProviders() ([]string, int, error)       { return nil, 0, ErrUnsupported }
func (unsupported) StorageProviders() ([]StorageProvider, int, error) { return nil, 0, ErrUnsupported }
func (unsupported) StorageProviderAlgorithms(string, uint32) ([]Algorithm, int, error) {
	return nil, 0, ErrUnsupported
}
func (unsupported) CSPs() ([]CSP, int, error)          { return nil, 0, ErrUnsupported }
func (unsupported) Probe(string, string) (bool, error) { return false, ErrUnsupported }
