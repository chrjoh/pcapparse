package krb5

import (
	"errors"
	"strconv"
	"time"

	"encoding/asn1"
	"encoding/hex"
)

// Message types
const (
	asRequestType     = 10
	principalNameType = 1
	cryptDesCbcMd4    = 2
	cryptDesCbcMd5    = 3
	cryptRc4Hmac      = 23
)

//Taken from
//https://github.com/heimdal/heimdal/blob/master/lib/asn1/krb5.asn1
var (
	asReqParam = "application,explicit,tag:10"
)

type principalName struct {
	NameType   int      `asn1:"explicit,tag:0"`
	NameString []string `asn1:"general,explicit,tag:1"`
}

type encryptedData struct {
	Etype  int    `asn1:"explicit,tag:0"`
	Kvno   int    `asn1:"optional,explicit,tag:1"`
	Cipher []byte `asn1:"explicit,tag:2"`
}

type ticket struct {
	TktVno  int           `asn1:"explicit,tag:0"`
	Realm   string        `asn1:"general,explicit,tag:1"`
	Sname   principalName `asn1:"explicit,tag:2"`
	EncPart encryptedData `asn1:"explicit,tag:3"`
}

type address struct {
	AddrType int    `asn1:"explicit,tag:0"`
	Address  []byte `asn1:"explicit,tag:1"`
}

type pnData struct {
	PnDataType  int    `asn1:"explicit,tag:1"`
	PnDataValue []byte `asn1:"explicit,tag:2"`
}

type kdcReq struct {
	Pvno    int        `asn1:"explicit,tag:1"`
	MsgType int        `asn1:"explicit,tag:2"`
	PnData  []pnData   `asn1:"optional,explicit,tag:3"`
	ReqBody kdcReqBody `asn1:"explicit,tag:4"`
}

type kdcReqBody struct {
	KDCOptions        asn1.BitString `asn1:"explicit,tag:0"`
	Cname             principalName  `asn1:"optional,explicit,tag:1"`
	Realm             string         `asn1:"general,explicit,tag:2"`
	Sname             principalName  `asn1:"optional,explicit,tag:3"`
	From              time.Time      `asn1:"generalized,optional,explicit,tag:4"`
	Till              time.Time      `asn1:"generalized,optional,explicit,tag:5"`
	Rtime             time.Time      `asn1:"generalized,optional,explicit,tag:6"`
	Nonce             int            `asn1:"explicit,tag:7"`
	Etype             []int          `asn1:"explicit,tag:8"`
	Addresses         []address      `asn1:"optional,explicit,tag:9"`
	EncAuthData       encryptedData  `asn1:"optional,explicit,tag:10"`
	AdditionalTickets []ticket       `asn1:"optional,explicit,tag:11"`
}

// $krb5$PnData[0].PnDataValue.Etype$Cname.NameString[0]$Realm$dummy$cipher
func (kdc kdcReq) String() (string, error) {
	var eType, cipher string
	var crypt []string
	realm := kdc.ReqBody.Realm

	if kdc.ReqBody.Cname.NameType == principalNameType {
		crypt = kdc.ReqBody.Cname.NameString
	}
	if len(crypt) != 1 {
		return "", errors.New("No crypt alg found")
	}
	for _, pn := range kdc.PnData {
		if pn.PnDataType == 2 {
			enc, _ := pn.getParsedValue()
			eType = strconv.Itoa(enc.Etype)
			cipher = hex.EncodeToString(enc.Cipher)
		}
	}
	if eType == "" || cipher == "" {
		return "", errors.New("No encryption type or cipher found")
	}
	hash := "$krb5$" + eType + "$" + crypt[0] + "$" + realm + "$nodata$" + cipher
	return hash, nil
}

func (pd pnData) getParsedValue() (encryptedData, error) {
	var encData encryptedData
	_, err := asn1.Unmarshal(pd.PnDataValue, &encData)
	if err != nil {
		return encryptedData{}, errors.New("Failed to parse pdata value")
	}
	return encData, nil
}
