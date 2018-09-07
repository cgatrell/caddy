package caddytls

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"github.com/mholt/caddy"
)


func init() {
	caddy.RegisterEventHook("ctmonitor", startMonitoring)
}

const (
	certSpotterAPIBase string = "https://api.certspotter.com/v1/issuances"
)
var (
	filePath string = filepath.Join(caddy.AssetsPath(), "ct_id")
	ct_config_file string = filepath.Join(caddy.AssetsPath(), "ct_config")
)

//The config struct will allow me to get the config data from a file
type CtConfig struct {
	IncludeSubdomains   bool  `json:"subdomains"`
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

// config is the configuration information for my queries.
type QueryConfig struct {
	Subdomains bool
	WildCards  bool
	Query      string
	Index      int
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
		//caddyCerts consists of the certificates that Caddy is serving.
		caddyCerts = make(map[string]struct{})

		//caddyDNS consists of the Subject Alternate Names that Caddy is hosting.
		caddyDNS = make([]string, 0, 10)
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

func getCertSpotterCerts(domainName string, config QueryConfig, biggestId *int, retrievedCerts map[string]string) (numOfIssuanceObjects int, issuanceId int, retryAfter string, err error) {
	// issuanceObjects consists of the issuanceObjects returned from CertSpotter.
	issuanceId = config.Index
	var (
		issuanceObjects []CertSpotterResponse
		certQuery string
		
	)
	certQuery = prepQuery(domainName, config)
	
	response, err := http.Get(certQuery)
	if err != nil {
		numOfIssuanceObjects = 0
		issuanceId = config.Index
		retryAfter = "3600"
		return numOfIssuanceObjects, issuanceId, retryAfter, fmt.Errorf("https get request failed on input %s\nError: %v", prepQuery(domainName, config), err)
	}
	defer response.Body.Close()
	
        err = json.NewDecoder(response.Body).Decode(&issuanceObjects)
	if err != nil {
		numOfIssuanceObjects = 0
		issuanceId = config.Index
		retryAfter = "3600"
		return numOfIssuanceObjects, issuanceId, retryAfter, fmt.Errorf("decoding json stream: %v", err)
	}
        
	numOfIssuanceObjects = len(issuanceObjects)
	fmt.Printf("Length of issuanceObjects: %v\n", numOfIssuanceObjects)
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
				issuanceId, err = strconv.Atoi(issuance.ID)
				if err != nil {
					issuanceId = config.Index
					retryAfter = "3600"
					return numOfIssuanceObjects, issuanceId, retryAfter, fmt.Errorf("error retrieving latest issuanceID: %v", err)
				}
				if issuanceId > *biggestId {
					*biggestId = issuanceId
				}
			}
		}
	} else {
		retryAfter = response.Header.Get("Retry-After")
		log.Printf("retryAfter: %v", retryAfter)
	}
	return
}


func getLatestIndex(fileName string) (int, error) {
	fmt.Printf("ct_id FilePath: %v\n", fileName)
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
	configJson, err := os.Open(ct_config_file)
	if err != nil {
		log.Printf("loadConfig error: %v", err)
	}
	defer configJson.Close()
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
//func lookUpNames(caddyCertSANs []string, query string, subdomains bool, wildcards bool, index int) (map[string]string, int) {
func lookUpNames(caddyCertsSANs []string, config QueryConfig) (map[string]string, int, err) {
	// retrievedCerts is the bytes of a certificate mapped to the 
	// ID, issuer name, and before/after values.
	retrievedCerts := make(map[string]string)

	
	var (
		// biggestId is the most recent certificate id returned from CertSpotter.
		biggestId int

		// timeToWait is the amount of time you need to wait before querying again.
		timeToWait int
	
		// retryAfter is the timeToWait value from the response headers.
		retryAfter string
	)
	for _, domainName := range caddyCertsSANs {
		retryAfter = queryDomainName(domainName, config, &biggestId, retrievedCerts)
	}
	err := putLatestId(biggestId, filePath)
	if err != nil {
		timeToWait = 3600
		return retrievedCerts, timeToWait, fmt.Errorf("writing latest ID: %v", err)
	}
	timeToWait, err = strconv.Atoi(retryAfter)
	if err != nil {
		log.Printf(err.Error())
		log.Print("Error retrieving time to wait, waiting 1 hour\n")
		timeToWait = 3600
	}
	return retrievedCerts, timeToWait, nil
}

// monitorCerts continuously monitors the certificates that Caddy serves, 
// it queries again after the specified time.
func monitorCerts() {
	var queryConfig QueryConfig
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

		queryConfig.Subdomains = config.IncludeSubdomains
		queryConfig.WildCards = config.IncludeWildCards
		queryConfig.Query = certSpotterAPIBase
		queryConfig.Index = startingIndex
		fetchedCerts, pause, err := lookUpNames(namesToLookUp, queryConfig)
		CompareCerts(caddyCerts, fetchedCerts)
		time.Sleep(time.Duration(pause) * time.Second)
	}
}

func prepQuery(domainName string, config QueryConfig) (query string) {
	v := url.Values{}
	v.Set("domain", domainName)
	if config.WildCards {
		v.Set("match_wildcards", "true")
	}
	if config.Subdomains {
		v.Set("include_subdomains", "true")
	}
	v.Set("after", strconv.Itoa(config.Index))
	v.Add("expand", "dns_names")
	v.Add("expand", "issuer")
	v.Add("expand", "cert")
	encodedValue := v.Encode()
	query = config.Query + "?" + encodedValue
	return query
}

func putLatestId(currentId int, fileName string) error {
	writeValue := strconv.Itoa(currentId)
	return ioutil.WriteFile(fileName, []byte(writeValue), 0600)
}

func queryDomainName(domainName string, config QueryConfig, biggestId *int, retrievedCerts map[string]string) string {
	var (
		querySize int
		retryAfter string
	)
	for ok := true; ok; ok = querySize > 0 {

		querySize, config.Index, retryAfter = getCertSpotterCerts(domainName, config, biggestId, retrievedCerts)
	}
	return retryAfter
}

func startMonitoring(eventType caddy.EventName, eventInfo interface{}) error {
	go monitorCerts()
	return nil
}
