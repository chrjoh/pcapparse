package ftp

import (
	"os"
	"regexp"
	"strings"

	"github.com/chrjoh/pcapparse/util"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type destAndPort struct {
	Destination string
	Port        layers.TCPPort
}

var (
	regExpFtp      = regexp.MustCompile("(USER|Password required|PASS)")
	regExpUsr      = regexp.MustCompile("USER")
	regExpRes      = regexp.MustCompile("Password required")
	regExpPass     = regexp.MustCompile("PASS")
	userRequest    = make(map[uint32]string)
	serverResponse = make(map[uint32]uint32)
	passRequest    = make(map[uint32]string)
	destPort       = make(map[uint32]destAndPort)
)

func Parse(inputFunc string, outputFunc string) {
	if handle, err := pcap.OpenOffline(inputFunc); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			if util.IsTcpPacket(packet) {
				handlePacket(packet)
			}
		}
		dumpFtp(outputFunc)
	}
}

// Extract the ftp login reposnses and requests
func handlePacket(packet gopacket.Packet) {
	app := packet.ApplicationLayer()
	if app == nil {
		return
	}
	n := len(app.Payload())
	values := strings.Split(string(app.Payload()[:n]), "\r\n")
	for _, s := range values {
		match := regExpFtp.FindString(s)
		if match != "" {
			if regExpUsr.FindString(s) != "" {
				tcp := packet.TransportLayer().(*layers.TCP)
				userRequest[tcp.Ack] = strings.Split(s, " ")[1]
				destPort[tcp.Ack] = destAndPort{
					Destination: util.GetDstIP(packet),
					Port:        tcp.DstPort,
				}
			} else if regExpRes.FindString(s) != "" {
				tcp := packet.TransportLayer().(*layers.TCP)
				serverResponse[tcp.Seq] = tcp.Ack
			} else if regExpPass.FindString(s) != "" {
				tcp := packet.TransportLayer().(*layers.TCP)
				passRequest[tcp.Seq] = strings.Split(s, " ")[1]
			}
		}
	}
}

func dumpFtp(outPutFile string) {
	file, _ := os.Create(outPutFile)
	file.WriteString("#USER:PASSWORD:DST-IP:PORT\n")
	defer file.Close()
	for uAck, user := range userRequest {
		srvSeq := serverResponse[uAck]
		password := passRequest[srvSeq]
		file.WriteString(user + ":" + password + ":" + destPort[uAck].Destination + ":" + destPort[uAck].Port.String() + "\n")
	}
}
