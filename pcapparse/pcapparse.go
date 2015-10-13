package pcapparse

import (
	"fmt"
	"os"

	"github.com/chrjoh/pcapparse/ftp"
	"github.com/chrjoh/pcapparse/ntlm"
)

// Parse parse the fiven file for ntlm or ftp user data
func Parse(typeFunc, inputFunc, outputFunc string) {

	switch typeFunc {
	case "ntlm":
		ntlm.Parse(inputFunc, outputFunc)
	case "ftp":
		ftp.Parse(inputFunc, outputFunc)
	default:
		fmt.Printf("Unknown type given: %v\n", typeFunc)
		os.Exit(0)
	}
}
