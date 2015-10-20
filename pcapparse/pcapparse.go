package pcapparse

import (
	"fmt"
	"os"

	"github.com/chrjoh/pcapparse/ftp"
	"github.com/chrjoh/pcapparse/krb5"
	"github.com/chrjoh/pcapparse/ntlm"
)

// Handler parse the fiven file for ntlm or ftp user data
func Handler(typeFunc, inputFunc, outputFunc string) {

	switch typeFunc {
	case "ntlm":
		ntlmHandler := ntlm.Parse(inputFunc)
		ntlmHandler.WriteToFile(outputFunc)
	case "ftp":
		ftpHandler := ftp.Parse(inputFunc)
		ftpHandler.WriteToFile(outputFunc)
	case "krb5":
		//krb.Parse(inputFunc)
		krbHandler := krb5.Parse(inputFunc)
		krbHandler.DumpStrings()
		//	krbHandler.WriteToFile(outputFunc)
	default:
		fmt.Printf("Unknown type given: %v\n", typeFunc)
		os.Exit(0)
	}
}
