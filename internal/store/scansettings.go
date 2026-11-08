package store

// Scan settings (0.5.1): the options a scan runs with, kept in the settings table so an
// administrator changes them in Settings instead of restarting the server with flags. An unset
// key means "as the server was started" (the command-line value is the default).

// Scan setting keys.
const (
	SettingHTTPChecks = "scan.http_checks" // "on" | "off"
	SettingCRL        = "scan.crl"         // "on" | "off"
	SettingCRLPrivate = "scan.crl_private" // "on" | "off"
)

// ScanSettings are the stored overrides; a nil field is unset (the command line decides).
type ScanSettings struct {
	HTTPChecks *bool
	CRL        *bool
	CRLPrivate *bool
}

func onOff(v string) *bool {
	switch v {
	case "on":
		b := true
		return &b
	case "off":
		b := false
		return &b
	}
	return nil
}

func wordOf(b *bool) string {
	switch {
	case b == nil:
		return ""
	case *b:
		return "on"
	}
	return "off"
}

// ScanSettings reads the stored scan settings.
func (s *Store) ScanSettings() (ScanSettings, error) {
	var out ScanSettings
	for _, k := range []struct {
		key string
		dst **bool
	}{{SettingHTTPChecks, &out.HTTPChecks}, {SettingCRL, &out.CRL}, {SettingCRLPrivate, &out.CRLPrivate}} {
		v, err := s.Setting(k.key)
		if err != nil {
			return ScanSettings{}, err
		}
		*k.dst = onOff(v)
	}
	return out, nil
}

// SetScanSettings stores the scan settings; a nil field clears the stored value, so the command
// line decides again.
func (s *Store) SetScanSettings(v ScanSettings) error {
	for _, k := range []struct {
		key string
		val *bool
	}{{SettingHTTPChecks, v.HTTPChecks}, {SettingCRL, v.CRL}, {SettingCRLPrivate, v.CRLPrivate}} {
		if err := s.SetSetting(k.key, wordOf(k.val)); err != nil {
			return err
		}
	}
	return nil
}
