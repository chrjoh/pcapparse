package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/chrjoh/pcapparse/ntlm"
)

// to crakc the passwords following john the ripper was used passwords.txt conatins list of passwords that are gonna be tested
// ./main -i steg3.pcap > test.lc
//john --format=netntlmv2 test.lc  --wordlist=passwords.txt --rules:KoreLogicRulesAppend4NumSpecial --pot=john.pot
var pcapFile = "steg3.pcap"

// Command line flags
var (
	inputFunc = flag.String("i", pcapFile, "Input file (.pcap)")
)

func main() {
	// Command line usage information
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "\nCommand line arguments:\n\n")
		flag.PrintDefaults()
		os.Exit(0)
	}

	// Parse the command line flags
	flag.Parse()
	ntlm.Parse(*inputFunc)
}
