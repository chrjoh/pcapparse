package ftp

import "testing"

func TestParseFile(t *testing.T) {
	result := Parse("../_fixtures/steg3.pcap")
	if len(result.userRequest) != 1 {
		t.Fatalf("Expected to find 1 user request but got: %v", len(result.userRequest))
	}
	if len(result.serverResponse) != 1 {
		t.Fatalf("Expected to find 1 server response but got: %v", len(result.serverResponse))
	}
	if len(result.passRequest) != 1 {
		t.Fatalf("Expected to find 1 password request but got: %v", len(result.passRequest))
	}
}
