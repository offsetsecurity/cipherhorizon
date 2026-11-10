package tlsprobe

// ParseTicket13ForTest exposes the TLS 1.3 ticket parser to the package's external tests.
func ParseTicket13ForTest(b []byte) (lifetime, maxEarlyData uint32, ok bool) {
	t, ok := parseTicket13(b)
	return t.lifetime, t.maxEarlyData, ok
}

// ChachaOpenForTest opens one ChaCha20-Poly1305 message with the package's own reader.
func ChachaOpenForTest(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	c := &chachaOpener{}
	copy(c.key[:], key)
	return c.Open(nil, nonce, ciphertext, aad)
}

// Tickets13ForTest reads the tickets out of a recorded TLS 1.3 server stream.
func Tickets13ForTest(stream []byte, keylog string, suite uint16) (n int, lifetime, maxEarlyData uint32, err error) {
	ts, err := tickets13(stream, keylog, suite)
	if len(ts) > 0 {
		lifetime, maxEarlyData = ts[0].lifetime, ts[0].maxEarlyData
	}
	return len(ts), lifetime, maxEarlyData, err
}
