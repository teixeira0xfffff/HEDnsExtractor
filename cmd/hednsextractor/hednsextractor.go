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
	utils.ParseStdin()
	utils.LoadParameters()

	if !utils.OptionCmd.Silent {
		utils.ShowBanner()
	}

	var workflow utils.Workflow
	if utils.OptionCmd.Workflow != "" {
		workflow.GetConf(utils.OptionCmd.Workflow)

		// Simplify workflow target processing
		processTargets(workflow.Domains)
		processTargets(workflow.Ipaddrs)
		processTargets(workflow.Networks)
	}

	hurricane := utils.Hurricane{}
	hurricane.RunCrawler()

	if utils.OptionCmd.Vtscore && !utils.OptionCmd.Silent {
		gologger.Info().Msgf("Filtering with Virustotal, minimum score: %s", utils.OptionCmd.VtscoreValue)
	}

	// Process results
	for _, result := range utils.Results {
		processResult(result, workflow)
	}

	displayOutputs() // Display results grouped by IP
}

// Processes workflow targets such as domains, IP addresses, or networks
func processTargets(targets []string) {
	for _, target := range targets {
		utils.IdentifyTarget(target)
	}
}

// Processes each result and applies regex and VirusTotal score filters
func processResult(result utils.Result, workflow utils.Workflow) {
	bMatchedDomain, bMatchedPTR := matchResultWithRegex(result, workflow.Regex)

	// Skip if no domain or PTR matches the regex
	if !bMatchedDomain && !bMatchedPTR {
		return
	}

	// Apply VirusTotal filter if enabled
	if utils.OptionCmd.Vtscore && !filterByVtScore(result) {
		return
	}

	// Group domains by IP
	if bMatchedDomain && result.Domain != "" {
		formatAndStoreResult(result.IPAddr, result.Domain, "Domain")
	}

	// Avoid PTR duplicates
	if bMatchedPTR && result.PTR != "" {
		ptrKey := fmt.Sprintf("%s:%s", result.IPAddr, result.PTR)
		if !ptrTracker[ptrKey] {
			ptrTracker[ptrKey] = true
			formatAndStoreResult(result.IPAddr, result.PTR, "PTR")
		}
	}
}

// Checks if the result matches the regex for both domain and PTR
func matchResultWithRegex(result utils.Result, regex string) (bool, bool) {
	if regex == "" {
		return true, true
	}
	re := regexp.MustCompile(regex)
	return re.MatchString(result.Domain), re.MatchString(result.PTR)
}

// Filters the result based on the VirusTotal score
func filterByVtScore(result utils.Result) bool {
	virustotal := utils.Virustotal{}
	result.VtScore = virustotal.GetVtReport(result.Domain)
	score, err := strconv.ParseUint(utils.OptionCmd.VtscoreValue, 10, 64)
	if err != nil {
		gologger.Fatal().Msg("Invalid value for vt-score")
		return false
	}
	return result.VtScore >= score
}

// Formats and stores the result in the outputs map
func formatAndStoreResult(ip, value, resultType string) {
	formattedValue := fmt.Sprintf("%s: %s", resultType, value)
	if utils.OptionCmd.Silent {
		outputs[ip] = append(outputs[ip], value)
	} else {
		prefix := "├─"
		if resultType == "PTR" {
			prefix = "└─"
		}
		outputs[ip] = append(outputs[ip], fmt.Sprintf("%s %s", prefix, formattedValue))
	}
}

// Displays the formatted outputs with colors and without PTR duplication
func displayOutputs() {
	ipColor := color.New(color.FgCyan).SprintFunc()
	domainColor := color.New(color.FgGreen).SprintFunc() // Green for domains
	ptrColor := color.New(color.FgYellow).SprintFunc()   // Yellow for PTRs

	for ip, entries := range outputs {
		gologger.Print().Msg("──────────────────────────────────────────")
		gologger.Print().Msgf(" IP: %s", ipColor(ip))

		var domains, ptrs []string
		for _, entry := range entries {
			if strings.Contains(entry, "Domain:") {
				domains = append(domains, entry)
			} else {
				ptrs = append(ptrs, entry)
			}
		}

		displayEntries(domains, domainColor)
		displayEntries(ptrs, ptrColor)
	}
}

// Displays the entries formatted with colors
func displayEntries(entries []string, colorFunc func(a ...interface{}) string) {
	for _, entry := range entries {
		coloredEntry := colorizeEntry(entry, colorFunc)
		if utils.OptionCmd.Silent {
			gologger.Silent().Msgf(coloredEntry)
		} else {
			gologger.Print().Msgf(" %s", coloredEntry)
		}
	}
}

// Applies color to the domain or PTR value
func colorizeEntry(entry string, colorFunc func(a ...interface{}) string) string {
	re := regexp.MustCompile(`: (.+)`)
	match := re.FindStringSubmatch(entry)
	if len(match) > 1 {
		coloredValue := colorFunc(match[1])
		return re.ReplaceAllString(entry, fmt.Sprintf(": %s", coloredValue))
	}
	return entry
}
