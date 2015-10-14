package pcapparse

import (
	"fmt"
	"os"

	"github.com/chrjoh/pcapparse/ftp"
	"github.com/chrjoh/pcapparse/ntlm"
)

// Handler parse the fiven file for ntlm or ftp user data
func Handler(typeFunc, inputFunc, outputFunc string) {

	switch typeFunc {
	case "ntlm":
		ntlmHandler := ntlm.Parse(inputFunc, outputFunc)
		ntlmHandler.WriteToFile(outputFunc)
	case "ftp":
		ftpHandler := ftp.Parse(inputFunc, outputFunc)
		ftpHandler.WriteToFile(outputFunc)
	default:
		fmt.Printf("Unknown type given: %v\n", typeFunc)
		os.Exit(0)
	}
}
