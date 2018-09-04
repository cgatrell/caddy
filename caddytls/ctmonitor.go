package caddytls

import (
	//"bufio"
	"encoding/base64"
	"encoding/json"
	//"fmt"
	"github.com/mholt/caddy"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)


func init() {
	caddy.RegisterEventHook("ctmonitor", startMonitoring)
}

const (
	certSpotterAPIBase string = "https://api.certspotter.com/v1/issuances"
)

var filePath string = filepath.Join(caddy.AssetsPath(), "ct_id")
//TODO Test the config unmarshal etc.  Test with data retrieved from API. See if I can check the log and get ID number?
//The config struct will allow me to get the config data from a file (I hope)
type CtConfig struct {
	IncludeSubdomains  bool  `json:"subdomains"`
	IncludeWildCards    bool  `json:"wildCards"`
}


// CertSpotterResponse is the json response formatting that is used in the program.
type CertSpotterResponse struct { 
	ID           string   `json:"id"`
	TBSSHA256    string   `json:"tbs_sha256"`
	DNSNames     []string `json:"dns_names"`
	PubKeySha256 string   `json:"pubkey_sha256"`
	Issuer       struct {
		Name         string `json:"name"`
		PubKeySha256 string `json:"pubkey_sha256"`
	} `json:"issuer"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
	Cert      struct {
		ID     string `json:"id"`
		Type   string `json:"type"`
		SHA256 string `json:"sha256"`
		Data   string `json:"data"`
	} `json:"cert"`
}

// compareCerts compares the certificates that caddy is serving against the certificates
// that certSpotter has found, if there are any that don't match the caddy certificates,
// they are reported to the user.
func CompareCerts(caddyCerts map[string]struct{}, certSpotterCerts map[string]string) {
	for key := range certSpotterCerts {
		if _, ok := caddyCerts[key]; !ok {
			log.Printf("[WARNING] Certificate found that caddy is not monitoring, issued by: %v\n", certSpotterCerts[key])
		}
	}
}

// getCaddyCerts retrieves the certificates that caddy monitors and returns them as a map
// with the key being the bytes of the certificate cast to a string.
func getCaddyCerts() ([]string, map[string]struct{}) {
	var (
		caddyCerts = make(map[string]struct{})//caddyCerts consists of the certificates that Caddy is serving.
		caddyDNS = make([]string, 0, 10)//caddyDNS consists of the Subject Alternate Names that Caddy is hosting.
	)
	for _, inst := range caddy.Instances() {
		inst.StorageMu.RLock()
		certCache, ok := inst.Storage[CertCacheInstStorageKey].(*certificateCache)
		inst.StorageMu.RUnlock()
		if !ok || certCache == nil {
			continue
		}
		certCache.RLock()
		for _, certificate := range certCache.cache {
			caddyDNS = append(caddyDNS, certificate.Names...)
			certBytes := string(certificate.Certificate.Certificate[0])
			if _, ok := caddyCerts[certBytes]; !ok {
				caddyCerts[certBytes] = struct{}{}
			}
		}
		certCache.RUnlock()
	}
	return caddyDNS, caddyCerts
}

func getLatestIndex(fileName string) (int, error) {
	indexBytes, err := ioutil.ReadFile(fileName)
	if os.IsNotExist(err) {
		log.Println("getLatestIndex failed, could not find the file")
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	indexStr := strings.TrimSpace(string(indexBytes))
	index, err := strconv.Atoi(indexStr)
	if err != nil {
		log.Println("Error converting file string to int.")
		return 0, err
	}
	return index, nil
}


func loadConfig() (config CtConfig) {
	configJson, err := os.Open("./ctConfig")
	if err != nil {
		log.Printf("loadConfig error: %v", err)
	}
	defer configJson.Close()
	//var config Config
	err = json.NewDecoder(configJson).Decode(&config)
	if err != nil {
		log.Printf("[NOTICE] jsonDecode failed, error: %v\nUsing default values", err)
		config.IncludeSubdomains = false
		config.IncludeWildCards = false
	}
	return
}

// lookUpNames queries the certSpotter service for each SAN that Caddy is hosting
// It then adds them to a set and returns a map of each certificate  mapped to a string
// that contains identifying information for the cert.
func lookUpNames(caddyCertSANs []string, query string, subdomains bool, wildcards bool, index int) (map[string]string, int) {
	// retrievedCerts is the bytes of a certificate mapped to the 
	// ID, issuer name, and before/after values.
	retrievedCerts := make(map[string]string)

	// biggestId is the most recent certificate id returned from CertSpotter.
	
	// timeToWait is the amount of time you need to wait before querying again.
	var biggestId, timeToWait int
	
	// retryAfter is the timeToWait value from the response headers.
	var retryAfter string

	// If the caddyCertSANs is empty, it shouldn't run this at all.
	for _, domainName := range caddyCertSANs {
		queryDomainName(domainName, query, subdomains, wildcards, index, &biggestId, retrievedCerts)
	}
	err := putLatestId(biggestId, filePath)// TODO if there was an error writing to the file, what should I do?
	if err != nil {
		//return fmt.Errorf("writing latest ID: %v", err)
		log.Printf("[WARNING] writing latest ID: %v", err)
	}
	timeToWait, err = strconv.Atoi(retryAfter)
	if err != nil {
		log.Printf(err.Error())
		log.Print("Error retrieving time to wait, waiting 1 hour\n")
		timeToWait = 3600
	}
	return retrievedCerts, timeToWait
}

// monitorCerts continuously monitors the certificates that Caddy serves, 
// it queries again after the specified time.
func monitorCerts() {
	config := loadConfig()
	for {
		namesToLookUp, caddyCerts := getCaddyCerts()
		if len(namesToLookUp) == 0 {
			log.Print("Could not retrieve DNS names from Caddy Certificate\n" +
                        "Make sure that you are serving on port 80 & 443\n" +
                        "Terminating monitorCerts.")
			break
		}
		startingIndex, err := getLatestIndex(filePath)
		if err != nil {
			log.Printf("Error %v while getting starting index, starting at 0", err)
		}
		fetchedCerts, pause := lookUpNames(namesToLookUp, certSpotterAPIBase, config.IncludeSubdomains, config.IncludeWildCards, startingIndex)
		CompareCerts(caddyCerts, fetchedCerts)
		time.Sleep(time.Duration(pause) * time.Second)
	}
}

func prepQuery(domainName string, subdomains bool, wildcards bool, index int, query string) string {
	v:= url.Values{}
	v.Set("domain", domainName)
	if wildcards {
		v.Set("match_wildcards", "true")
	}
	if subdomains {
		v.Set("include_subdomains", "true")
	}
	v.Set("after", strconv.Itoa(index))
	v.Add("expand", "dns_names")
	v.Add("expand", "issuer")
	v.Add("expand", "cert")
	encodedValue := v.Encode()
	
	return query + "?" + encodedValue
}

func putLatestId(currentId int, fileName string) error {
	writeValue := strconv.Itoa(currentId)
	return ioutil.WriteFile(fileName, []byte(writeValue), 0600)
}

func queryDomainName(domainName string, query string, subdomains bool, wildcards bool, index int, biggestId *int, retrievedCerts map[string]string) string {
	// concurrent is set to the last certificate id for each paged result.
	var (
		concurrent int
		querySize int
		retryAfter string
	)
	concurrent = index
	
	for ok := true; ok; ok = querySize > 0 {
		//fucn
		querySize, concurrent, retryAfter = getCertSpotterCerts(domainName, query, subdomains, wildcards, concurrent, biggestId, retrievedCerts)
	}
	//After I have queried the DomainName, I want to return the retryAfter value. I probably don't need to return the map...
	return retryAfter //TODO after the loop that executes queryDomainName, I will want to convert the final retryAfter to an int and then write biggestId to a file 
}
			


func startMonitoring(eventType caddy.EventName, eventInfo interface{}) error {
	go monitorCerts()
	return nil
}


func getCertSpotterCerts(domainName string, query string, subdomains bool, wildcards bool, index int, biggestId *int, retrievedCerts map[string]string) (numOfIssuanceObjects int, issuanceId int, retryAfter string) {
	// issuanceObjects consists of the issuanceObjects returned from CertSpotter.
	var (
		issuanceObjects []CertSpotterResponse
		certQuery string
		
	)
	certQuery = prepQuery(domainName,
		subdomains, wildcards, index, query)
	
	response, err := http.Get(certQuery)
	if err != nil {
		log.Printf("https get request failed on input %s \nError: %v", prepQuery(domainName, subdomains, wildcards, index, query), err)
	}
	defer response.Body.Close()
	
        err = json.NewDecoder(response.Body).Decode(&issuanceObjects)// handle error
	if err != nil {
		//return fmt.Errorf("decoding json stream: %v", err)
		log.Printf("[WARNING] error decoding json stream: %v", err)
	}
        
	numOfIssuanceObjects = len(issuanceObjects)
	if numOfIssuanceObjects > 0 {
		for i, issuance := range issuanceObjects {
			bytes, err := base64.StdEncoding.DecodeString(issuance.Cert.Data)
			if err != nil {
				log.Printf("Decoding failed: %v", err)
			}
			aKey := string(bytes)
			if _, ok := retrievedCerts[aKey]; ok {
				continue
			}
			if issuance.Cert.Type == "precert" {
				continue
			}
			value := "ID: " + issuance.Cert.ID + " " + issuance.Issuer.Name + " not valid before: " + issuance.NotBefore +
				" and not valid after: " + issuance.NotAfter
			retrievedCerts[aKey] = value
			if i == numOfIssuanceObjects - 1 {
				issuanceId, err := strconv.Atoi(issuance.ID)
				if err != nil {
					log.Printf(err.Error())
					log.Print("Error occured on line 277 of ctmonitor")
				}
				if issuanceId > *biggestId {
					*biggestId = issuanceId
				}
				//concurrent = issuanceId I don't think I need this anymore because I am returning the value and processing it after the function returns.
			}
		}
	} else {
		retryAfter = response.Header.Get("Retry-After")
		log.Printf("retryAfter: %v", retryAfter)
	}

	return
}
