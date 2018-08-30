package caddytls

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"
	"testing"
)

func TestCompareCerts(t *testing.T) {
	caddyCert, err := ioutil.ReadFile("testInputs/serverCert.txt")
	if err != nil {
		fmt.Println("Error reading ServerCert.txt")
	}
	jsonData, err := ioutil.ReadFile("testInputs/testJson.json")
	if err != nil {
		fmt.Println("Error reading testJson.json")
	}
	
	caddyCertString := strings.TrimSpace(string(caddyCert))
	caddyCerts := make(map[string]struct{})
	retrievedCerts := make(map[string]string)
	caddyCerts[string(DecodeField(caddyCertString))] = struct{}{}

	var issuanceObjects []SslmateStruct
	if err := json.Unmarshal(jsonData, &issuanceObjects); err != nil {
		fmt.Printf("Unmarshal failed: %#v\n", err)
	}
	for _, issuance := range issuanceObjects {
		bytes := DecodeField(issuance.Cert.Data)
		aKey := string(bytes)
		if _, ok := retrievedCerts[aKey]; ok {
			continue
		} else {
			if issuance.Cert.Type == "precert" {
				continue
			}
			value := "ID: " + issuance.Cert.ID + " " + issuance.Issuer.Name + " not valid before: " + issuance.NotBefore +
				" and not valid after: " + issuance.NotAfter
			retrievedCerts[aKey] = value
		} 
	}
	fmt.Printf("len of retrievedCerts: %v\n", len(retrievedCerts))
	CompareCerts(caddyCerts, retrievedCerts)//4 should be flagged while only one is a match.
}//End of test


/*func TestPrepQuery(t *testing.T) {
	fmt.Println(BASE_URI + prepQuery("gocyrus.net", false, false, 0))
}*/

