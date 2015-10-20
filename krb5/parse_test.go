package krb5

import "testing"

func TestTSRequests(t *testing.T) {
	result := Parse("../_fixtures/krb-816.cap")

	if len(result.KrbRequests) != 4 {
		t.Fatalf("Expected to find 4 AS requests but got: %v", len(result.KrbRequests))
	}
}
