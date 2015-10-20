package krb5

import (
	"encoding/asn1"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type krbAuth struct {
	KrbRequests []kdcReq
}

func (krb *krbAuth) addKdcReq(kdc kdcReq) {
	krb.KrbRequests = append(krb.KrbRequests, kdc)
}

// NewKrbHandler returns a krbAuth for handling package selects
func NewKrbHandler() *krbAuth {
	return &krbAuth{[]kdcReq{}}
}

// DumpStrings print all krb5 data to stdout
func (kdc krbAuth) DumpStrings() {
	for _, val := range kdc.KrbRequests {
		data, _ := val.String()
		fmt.Println(data)
	}
}

// HandlePacket extract the krb5 AS-Requests
func (krb *krbAuth) HandlePacket(packet gopacket.Packet) {
	app := packet.ApplicationLayer()
	if app == nil {
		return
	}
	udp := packet.TransportLayer().(*layers.UDP)

	//KRB_AS_REQ.padata.PA-ENC-TIMESTAMP.Value.encPA_ENC_TIMESTAMP
	//checksum = 16 first bytes of ENC_PA_ENC_TIMESTAMP
	//encrypted_data = ENC_PA_ENC_TIMESTAMP starting at byte 17 (i.e. ENC_PA_ENC_TIMESTAMP without the checksum)
	//pwd: the round password being tried

	//http://john-users.openwall.narkive.com/kGRlTMyG/john-the-ripper-for-kerberos-ticket
	//https://github.com/piyushcse29/john-the-ripper/blob/master/src/KRB5_fmt_plug.c
	if udp.DstPort == 88 {
		var n kdcReq
		_, err := asn1.UnmarshalWithParams(app.Payload(), &n, asReqParam)
		if err != nil {
			return
		}
		if n.MsgType == asRequestType {
			krb.addKdcReq(n)
		}
	}
}

// HandlePacketTmp used in development to display package data
func (krb *krbAuth) HandlePacketTmp(packet gopacket.Packet) {
	app := packet.ApplicationLayer()
	if app == nil {
		return
	}
	udp := packet.TransportLayer().(*layers.UDP)

	if udp.DstPort == 88 {
		msgType := app.Payload()[17:18]
		if msgType[0] == 10 { // AS-REQ type = 10
			var n kdcReq
			_, err := asn1.UnmarshalWithParams(app.Payload(), &n, asReqParam)
			if err != nil {
				fmt.Println("Error in asn.1 parse")
				fmt.Println(err)
			} else {
				fmt.Println("-------------------------------")
				fmt.Printf("PnDataType: %v\n", n.PnData[0].PnDataType)
				//fmt.Println(hex.Dump(n.Pdata[0].PdataValue))
				var encData encryptedData
				asn1.Unmarshal(n.PnData[0].PnDataValue, &encData)
				fmt.Printf("Etype: %v\n", encData.Etype)
				fmt.Printf("Kvno: %v\n", encData.Kvno)
				//fmt.Println(hex.Dump(encData.Cipher))
				//fmt.Println(len(encData.Cipher))
				fmt.Printf("Cname: %v\n", n.ReqBody.Cname)
				fmt.Printf("Sname %v\n", n.ReqBody.Sname)
				fmt.Printf("Realm: %v\n", n.ReqBody.Realm)

			}
		}
	}
}
