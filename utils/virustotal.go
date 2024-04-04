package utils

import (
	"fmt"
	"net/http/httputil"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/tidwall/gjson"
)

type Virustotal struct {
}

const vt_url = "https://www.virustotal.com"

func (c *Virustotal) GetVtReport(domain string) uint64 {
	urlBase := fmt.Sprintf("%s/api/v3/domains/%s", vt_url, domain)

	str := c.request(urlBase)

	malicious := gjson.Get(str, "data.attributes.last_analysis_stats.malicious")
	suspicious := gjson.Get(str, "data.attributes.last_analysis_stats.suspicious")
	vtScore := malicious.Uint() + suspicious.Uint()
	return vtScore
}

func (c *Virustotal) request(urlBase string) string {
	request, err := retryablehttp.NewRequest("GET", urlBase, nil)
	if err != nil {
		gologger.Fatal().Msgf("err: %v", err)
	}
	request.Header.Set("x-apikey", OptionCmd.VtApiKey)

	opts := retryablehttp.DefaultOptionsSpraying
	client := retryablehttp.NewClient(opts)
	response, err := client.Do(request)
	if err != nil {
		panic(err)
	}

	bin, err := httputil.DumpResponse(response, true)
	if err != nil {
		panic(err)
	}
	str := string(bin)
	return str
}
