package refdata

import "time"

// The maximum validity of a publicly trusted TLS server certificate, by the
// date it was issued. Transcribed by hand from CA/Browser Forum Ballot SC-081v3
// (amending Baseline Requirements §6.3.2), adopted 2025-04-11. It is short,
// rarely changes and has no machine-readable source, so it is written here and
// pinned by TestLifetimeTablePinned: change both together, from the ballot.

var lifetimeSource = Source{
	Name:      "Certificate lifetime limits",
	URL:       "https://cabforum.org/2025/04/11/ballot-sc081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/",
	Retrieved: "2026-10-02",
	SHA256:    "",
	Licence:   "Transcribed from CA/Browser Forum Ballot SC-081v3; factual schedule",
}

// LifetimeLimit is the maximum validity for certificates issued on or after From.
type LifetimeLimit struct {
	From time.Time
	Days int
}

var lifetimeLimits = []LifetimeLimit{
	{From: time.Date(2020, 9, 1, 0, 0, 0, 0, time.UTC), Days: 398},
	{From: time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC), Days: 200},
	{From: time.Date(2027, 3, 15, 0, 0, 0, 0, time.UTC), Days: 100},
	{From: time.Date(2029, 3, 15, 0, 0, 0, 0, time.UTC), Days: 47},
}

// LifetimeSourceLabel names the rule a limit comes from.
const LifetimeSourceLabel = "CA/B Forum BR §6.3.2 (Ballot SC-081v3)"

// MaxLifetime returns the limit for a certificate issued at notBefore, and
// false when it was issued before the first entry (no limit is applied).
func MaxLifetime(notBefore time.Time) (int, bool) {
	days, ok := 0, false
	for _, l := range lifetimeLimits {
		if !notBefore.Before(l.From) {
			days, ok = l.Days, true
		}
	}
	return days, ok
}

// LifetimeTable returns a copy of the schedule.
func LifetimeTable() []LifetimeLimit { return append([]LifetimeLimit(nil), lifetimeLimits...) }
