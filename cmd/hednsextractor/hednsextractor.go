package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/HuntDownProject/hednsextractor/utils"
	"github.com/fatih/color"
	"github.com/projectdiscovery/gologger"
)

var (
	outputs    = make(map[string][]string) // Map to group domains by IP
	ptrTracker = make(map[string]bool)     // Map to track PTRs that have already been added
)

func main() {
	// Parse the standard input
	utils.ParseStdin()

	// Load parameters from command line and configuration file
	utils.LoadParameters()

	// Show banner
	utils.ShowBanner()

	// Read the Workflow from YAML
	var workflow utils.Workflow
	if utils.OptionCmd.Workflow != "" {
		workflow.GetConf(utils.OptionCmd.Workflow)

		// Simplify workflow loops
		for _, domain := range workflow.Domains {
			utils.IdentifyTarget(domain)
		}

		for _, ipaddr := range workflow.Ipaddrs {
			utils.IdentifyTarget(ipaddr)
		}

		for _, network := range workflow.Networks {
			utils.IdentifyTarget(network)
		}
	}

	hurricane := utils.Hurricane{}
	hurricane.RunCrawler()

	if utils.OptionCmd.Vtscore && !utils.OptionCmd.Silent {
		gologger.Info().Msgf("Filtering with Virustotal with a minimum score %s", utils.OptionCmd.VtscoreValue)
	}

	// Process results
	for _, result := range utils.Results {
		processResult(result, workflow)
	}

	// Display results grouped by IP
	displayOutputs()
}

// Processes each result and applies Regex and Vtscore filters
func processResult(result utils.Result, workflow utils.Workflow) {
	var bMatchedPTR, bMatchedDomain = matchResultWithRegex(result, workflow.Regex)

	// If no domain or PTR matches the regex, continue
	if !bMatchedDomain && !bMatchedPTR {
		return
	}

	// Apply VirusTotal filter if enabled
	if utils.OptionCmd.Vtscore && !filterByVtScore(result) {
		return
	}

	// Group domains by IP
	if bMatchedDomain && result.Domain != "" {
		outputs[result.IPAddr] = append(outputs[result.IPAddr], fmt.Sprintf("├─ Domain: %s", result.Domain))
	}

	// Check if the PTR has already been added to avoid duplicates
	if bMatchedPTR && result.PTR != "" {
		ptrKey := fmt.Sprintf("%s:%s", result.IPAddr, result.PTR)
		if !ptrTracker[ptrKey] { // If it hasn't been added yet
			// PTR will be added at the end
			ptrTracker[ptrKey] = true // Mark the PTR as added
			outputs[result.IPAddr] = append(outputs[result.IPAddr], fmt.Sprintf("└─ PTR: %s", result.PTR))
		}
	}
}

// Checks if the result matches the regex for domain and PTR
func matchResultWithRegex(result utils.Result, regex string) (bool, bool) {
	if regex != "" {
		re := regexp.MustCompile(regex)
		return re.MatchString(result.Domain), re.MatchString(result.PTR)
	}
	return true, true
}

// Filters the result based on the VirusTotal score
func filterByVtScore(result utils.Result) bool {
	virustotal := utils.Virustotal{}
	result.VtScore = virustotal.GetVtReport(result.Domain)
	if score, err := strconv.ParseUint(utils.OptionCmd.VtscoreValue, 10, 64); err == nil {
		return result.VtScore >= score
	} else {
		gologger.Fatal().Msg("Invalid parameter value for vt-score")
		return false
	}
}

// Displays the formatted output with separators, without PTR duplication, with PTR at the end, and with colors
func displayOutputs() {
	// Define colors
	ipColor := color.New(color.FgCyan).SprintFunc()
	domainColor := color.New(color.FgGreen).SprintFunc() // Green for domains
	ptrColor := color.New(color.FgYellow).SprintFunc()   // Yellow for PTRs

	for ip, entries := range outputs {
		// Add a separator line before each group
		gologger.Print().Msg("──────────────────────────────────────────")
		// Display the IP with color
		gologger.Print().Msgf(" IP: %s", ipColor(ip))

		// Lists to separate domains and PTRs
		var domains, ptrs []string

		// Separate domains and PTRs
		for _, entry := range entries {
			if strings.Contains(entry, "Domain:") {
				domains = append(domains, entry)
			} else {
				ptrs = append(ptrs, entry)
			}
		}

		// Display the domains with color
		for _, domain := range domains {
			// Apply color to the domain
			gologger.Print().Msgf(" %s", colorizeEntry(domain, domainColor))
		}

		// Display the PTRs with color at the end
		for _, ptr := range ptrs {
			// Apply color to the PTR
			gologger.Print().Msgf(" %s", colorizeEntry(ptr, ptrColor))
		}
	}
}

// Replaces the value of the domain or PTR with the colored version
func colorizeEntry(entry string, colorFunc func(a ...interface{}) string) string {
	re := regexp.MustCompile(`: (.+)`)
	match := re.FindStringSubmatch(entry)
	if len(match) > 1 {
		// Apply color directly to the value after the ":"
		coloredValue := colorFunc(match[1])
		return re.ReplaceAllString(entry, fmt.Sprintf(": %s", coloredValue))
	}
	return entry
}
