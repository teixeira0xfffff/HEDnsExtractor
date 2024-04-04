package main

import (
	"fmt"
	"regexp"
	"strconv"

	"github.com/HuntDownProject/hednsextractor/utils"
	"github.com/projectdiscovery/gologger"
)

var (
	outputs []string
)

func main() {

	// Parse the stdin
	utils.ParseStdin()

	// Load parameters from command line and configuration file
	utils.LoadParameters()

	// Show Banner
	utils.ShowBanner()

	// read the Workflow from yaml
	var workflow utils.Workflow
	if utils.OptionCmd.Workflow != "" {
		workflow.GetConf(utils.OptionCmd.Workflow)

		for i := range workflow.Domains {
			utils.IdentifyTarget(workflow.Domains[i])
		}

		for i := range workflow.Ipaddrs {
			utils.IdentifyTarget(workflow.Ipaddrs[i])
		}

		for i := range workflow.Networks {
			utils.IdentifyTarget(workflow.Networks[i])
		}
	}

	hurricane := utils.Hurricane{}
	hurricane.RunCrawler()

	if utils.OptionCmd.Vtscore && !utils.OptionCmd.Silent {
		gologger.Info().Msgf("Filtering with Virustotal with a mininum score %s", utils.OptionCmd.VtscoreValue)
	}

	for _, result := range utils.Results {
		var bMatchedPTR = false
		var bMatchedDomain = false

		if workflow.Regex != "" {
			var re = regexp.MustCompile(workflow.Regex)
			bMatchedDomain = re.MatchString(result.Domain)
			bMatchedPTR = re.MatchString(result.PTR)
		} else {
			bMatchedPTR = true
			bMatchedDomain = true
		}

		if !bMatchedDomain && !bMatchedPTR {
			continue
		}

		if utils.OptionCmd.Vtscore {
			virustotal := utils.Virustotal{}
			result.VtScore = virustotal.GetVtReport(result.Domain)
			if score, err := strconv.ParseUint(utils.OptionCmd.VtscoreValue, 10, 64); err == nil {
				if result.VtScore < score {
					continue
				}
			} else {
				gologger.Fatal().Msg("Invalid parameter value for vt-score")
			}
		}

		var output = prepareOutput(result, bMatchedDomain, bMatchedPTR)
		if !utils.Contains(outputs, output) {
			outputs = append(outputs, output)
		}
	}

	for _, output := range outputs {
		if utils.OptionCmd.Silent {
			gologger.Silent().Msgf(output)
		} else {
			gologger.Info().Msgf(output)
		}
	}
}

func prepareOutput(result utils.Result, bMatchedDomain bool, bMatchedPTR bool) string {
	var output = ""

	if bMatchedDomain && result.Domain != "" {
		if utils.OptionCmd.Silent {
			output = fmt.Sprintf("%s\n", result.Domain)
		} else {
			output = fmt.Sprintf("[%s] domain: %s", result.IPAddr, result.Domain)
		}
	}

	if bMatchedPTR && result.PTR != "" {
		if utils.OptionCmd.Silent {
			output = fmt.Sprintf("%s\n", result.PTR)
		} else {
			output = fmt.Sprintf("[%s] PTR: %s", result.IPAddr, result.PTR)
		}
	}

	if !utils.OptionCmd.Silent {
		if utils.OptionCmd.Vtscore {
			output = fmt.Sprintf("%s VT Score: %d", output, result.VtScore)
		}
	}
	return output
}
