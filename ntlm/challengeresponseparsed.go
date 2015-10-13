package ntlm

type challengeResponseParsed struct {
	Type      int
	User      string
	Domain    string
	LmHash    string
	NtHashOne string
	NtHashTwo string
}

// LcString return the challenge response data as lc string
func (data challengeResponseParsed) LcString(serverChallenge string) string {
	// NTLM v1 in .lc format
	if data.Type == NtlmV1 {
		return data.User + "::" + data.Domain + ":" + data.LmHash + ":" + serverChallenge + "\n"
	}
	return data.User + "::" + data.Domain + ":" + serverChallenge + ":" + data.NtHashOne + ":" + data.NtHashTwo + "\n"
}
