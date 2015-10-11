package ftp

import (
	"os"
	"regexp"
	"strings"

	"github.com/chrjoh/pcapparse/util"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type destAndPort struct {
	Destination string
	Port        layers.TCPPort
}

type ftpLogin struct {
	userRequest    map[uint32]string
	serverResponse map[uint32]uint32
	passRequest    map[uint32]string
	destPort       map[uint32]destAndPort
}

var (
	regExpFtp  = regexp.MustCompile("(USER|Password required|PASS)")
	regExpUsr  = regexp.MustCompile("USER")
	regExpSrv  = regexp.MustCompile("Password required")
	regExpPass = regexp.MustCompile("PASS")
)

// NewFtpHandler returns a ftplogin for handling package selects
func NewFtpHandler() *ftpLogin {
	return &ftpLogin{
		userRequest:    make(map[uint32]string),
		serverResponse: make(map[uint32]uint32),
		passRequest:    make(map[uint32]string),
		destPort:       make(map[uint32]destAndPort),
	}
}

func (ftp *ftpLogin) user(key uint32, value string) {
	ftp.userRequest[key] = value
}

func (ftp *ftpLogin) server(key, value uint32) {
	ftp.serverResponse[key] = value
}

func (ftp *ftpLogin) pass(key uint32, value string) {
	ftp.passRequest[key] = value
}

func (ftp *ftpLogin) destination(key uint32, value destAndPort) {
	ftp.destPort[key] = value
}

// Extract the ftp login reposnses and requests
func (ftp *ftpLogin) handlePacket(packet gopacket.Packet) {
	app := packet.ApplicationLayer()
	if app == nil {
		return
	}
	n := len(app.Payload())
	values := strings.Split(string(app.Payload()[:n]), "\r\n")
	for _, s := range values {
		match := regExpFtp.FindString(s)
		if match != "" {
			tcp := packet.TransportLayer().(*layers.TCP)
			if regExpUsr.FindString(s) != "" {
				ftp.user(tcp.Ack, strings.Split(s, " ")[1])
				ftp.destination(tcp.Ack, destAndPort{
					Destination: util.GetDstIP(packet),
					Port:        tcp.DstPort,
				})
			} else if regExpSrv.FindString(s) != "" {
				ftp.server(tcp.Seq, tcp.Ack)
			} else if regExpPass.FindString(s) != "" {
				ftp.pass(tcp.Seq, strings.Split(s, " ")[1])
			}
		}
	}
}

func (ftp ftpLogin) dump(outPutFile string) {
	file, _ := os.Create(outPutFile)
	file.WriteString("#USER:PASSWORD:DST-IP:PORT\n")
	defer file.Close()
	for uAck, user := range ftp.userRequest {
		srvSeq := ftp.serverResponse[uAck]
		password := ftp.passRequest[srvSeq]
		file.WriteString(user + ":" + password + ":" + ftp.destPort[uAck].Destination + ":" + ftp.destPort[uAck].Port.String() + "\n")
	}
}
