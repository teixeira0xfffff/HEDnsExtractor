package utils

import (
	"io"
	"net/http"
	"net/http/httputil"
	"regexp"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/corpix/uarand"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/retryablehttp-go"
)

// CustomTransport struct that embeds http.RoundTripper
type CustomTransport struct {
	Transport http.RoundTripper
	UserAgent string
}

// RoundTrip method to add the custom User-Agent header
func (c *CustomTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", c.UserAgent)
	return c.Transport.RoundTrip(req)
}

type Hurricane struct {
}

const urlBase = "https://bgp.he.net/"

func (h *Hurricane) RunCrawler() {
	for _, domain := range Domains {
		gologger.Verbose().Msgf("Identifying networks for domain: %s", domain)
		h.ExtractDomain(domain)
	}

	for _, host := range Hosts {
		gologger.Verbose().Msgf("Identifying networks for IPv4: %s", host)
		h.ExtractNetwork(host)
	}

	if !OptionCmd.Onlynetworks {
		for _, network := range Networks {
			gologger.Verbose().Msgf("Identifying domains for network: %s", network)
			h.ExtractDomains(network)
		}
	}
}

func (h *Hurricane) Request(url string) string {

	// Create a custom transport with the desired User-Agent
	customTransport := &CustomTransport{
		Transport: http.DefaultTransport,
		UserAgent: uarand.GetRandom(),
	}

	opts := retryablehttp.DefaultOptionsSpraying
	client := retryablehttp.NewClient(opts)

	// uses the custom transport
	client.HTTPClient.Transport = customTransport

	// adjust the timeout
	client.HTTPClient.Timeout = time.Duration(OptionCmd.Timeout) * time.Second

	resp, err := client.Get(url)
	if err != nil {
		gologger.Fatal().Msgf("Could not get the response from the server: %s\n", err)
	}

	bin, err := httputil.DumpResponse(resp, true)
	if err != nil {
		gologger.Fatal().Msgf("Could not dump the response from the server: %s\n", err)
	}
	str := string(bin)

	return str
}

func (h *Hurricane) ExtractDomain(domain string) {
	var url = ""

	if domain != "" {
		url = urlBase + "dns/" + domain + "#_dns"
	}

	var str = h.Request(url)

	var re = regexp.MustCompile(`(?m)href="/net/([^"]+)"`)
	for _, match := range re.FindAllStringSubmatch(str, -1) {
		if !Contains(Networks, match[1]) {
			if (!OptionCmd.Silent && !OptionCmd.Onlydomains) || OptionCmd.Onlynetworks {
				gologger.Info().Msgf("[%s] network: %s\n", domain, match[1])
			}
			Networks = append(Networks, match[1])
		}
	}
}

func (h *Hurricane) ExtractDomains(ipRange string) {
	if ipRange == "" {
		return
	}

	var url = urlBase + "net/" + ipRange + "#_dnsrecords"
	var html = h.Request(url)

	h.ParseHTML(strings.NewReader(html))
}

func (h *Hurricane) ParseHTML(body io.Reader) {
	doc, err := goquery.NewDocumentFromReader(body)
	if err != nil {
		gologger.Fatal().Msgf("%s", err)
	}
	var re = regexp.MustCompile(`\/dns\/([^"]+)`)

	doc.Find("#dnsrecords").Each(func(h int, div *goquery.Selection) {

		div.Find("tr").Each(func(i int, tr *goquery.Selection) {
			var result Result
			tr.Find("td").Each(func(j int, td *goquery.Selection) {
				td.Find("a").Each(func(k int, a *goquery.Selection) {
					switch td.Index() {
					case 0:
						result.IPAddr = a.Text()
					case 1:
						result.PTR = a.Text()
					case 2:
						html, err := td.Html()
						if err == nil {
							for _, match := range re.FindAllStringSubmatch(html, -1) {
								result.Domain = match[1]
								Results[result.Domain] = result
							}
						}
					}
				})
			})
		})
	})
}

func (h *Hurricane) ExtractNetwork(ip string) {
	var url = ""

	if ip != "" {
		url = urlBase + "ip/" + ip
	}

	var str = h.Request(url)

	if ip != "" {
		var re = regexp.MustCompile(`(?m)href="/net/([^"]+)"`)
		for _, match := range re.FindAllStringSubmatch(str, -1) {
			if !Contains(Networks, match[1]) {
				if (!OptionCmd.Silent && !OptionCmd.Onlydomains) || OptionCmd.Onlynetworks {
					gologger.Info().Msgf("[%s] network: %s\n", ip, match[1])
				}
				Networks = append(Networks, match[1])
			}
		}
	}
}
