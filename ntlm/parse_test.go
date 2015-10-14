package ntlm

import "testing"

func TestParseFile(t *testing.T) {
	result := Parse("../_fixtures/steg3.pcap")
	if len(result.serverResponsePairs) != 33 {
		t.Fatalf("Expected to find 33 pairs but got: %v", len(result.serverResponsePairs))
	}
}

func TestCompleteHandshakes(t *testing.T) {
	result := Parse("../_fixtures/steg3.pcap")
	count := 0

	for _, sr := range result.serverResponsePairs {
		r := sr.getResponseHeader()
		if r.UserLen != 0 {
			count += 1
		}
	}
	if count != 14 {
		t.Fatalf("Expected to find 14 pairs but got: %v", count)
	}
}
