package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/chrjoh/pcapparse/pcapparse"
)

// to crack the passwords following john the ripper was used passwords.txt conatins list of passwords that are gonna be tested
// ./main -i steg3.pcap -o output_steg3.lc
//john --format=netntlmv2 output_steg3.lc  --wordlist=passwords.txt --rules:KoreLogicRulesAppend4NumSpecial --pot=john.pot
var (
	pcapFile   = "steg3.pcap"
	outputFile = "output_steg3.lc"
	// Command line flags
	inputFunc  = flag.String("i", pcapFile, "Input file (.pcap)")
	outputFunc = flag.String("o", outputFile, "Output file (.lc)")
	typeFunc   = flag.String("t", "ntlm", "Type select what tor parse the pcap file for, options: ntlm, ftp")
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

	pcapparse.Handler(*typeFunc, *inputFunc, *outputFunc)
}
