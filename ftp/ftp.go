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

// Extract the ftp login reposnses and requests
func (ftp *ftpLogin) HandlePacket(packet gopacket.Packet) {
	app := packet.ApplicationLayer()
	if app == nil {
		return
	}
	n := len(app.Payload())
	values := strings.Split(string(app.Payload()[:n]), "\r\n")
	for _, s := range values {
		if isFtp(s) {
			tcp := packet.TransportLayer().(*layers.TCP)
			if isUser(s) {
				ftp.user(tcp.Ack, strings.Split(s, " ")[1])
				ftp.destination(tcp.Ack, destAndPort{
					Destination: util.GetDstIP(packet),
					Port:        tcp.DstPort,
				})
			} else if isServer(s) {
				ftp.server(tcp.Seq, tcp.Ack)
			} else if isPass(s) {
				ftp.pass(tcp.Seq, strings.Split(s, " ")[1])
			}
		}
	}
}

//WriteToFile store the result on the given file
func (ftp ftpLogin) WriteToFile(outPutFile string) {
	file, _ := os.Create(outPutFile)
	defer file.Close()
	file.WriteString("#USER:PASSWORD:DST-IP:PORT\n")
	for uAck, user := range ftp.userRequest {
		srvSeq := ftp.serverResponse[uAck]
		password := ftp.passRequest[srvSeq]
		file.WriteString(user + ":" + password + ":" + ftp.destPort[uAck].Destination + ":" + ftp.destPort[uAck].Port.String() + "\n")
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

func isUser(s string) bool {
	return regExpUsr.FindString(s) != ""
}

func isServer(s string) bool {
	return regExpSrv.FindString(s) != ""
}

func isPass(s string) bool {
	return regExpPass.FindString(s) != ""
}

func isFtp(s string) bool {
	return regExpFtp.FindString(s) != ""
}
