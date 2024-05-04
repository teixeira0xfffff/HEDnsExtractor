package utils

import (
	"bufio"
	"os"

	fileutil "github.com/projectdiscovery/utils/file"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

func ParseStdin() {
	// Look into stdin to grab the IPv4s and Networks
	if fileutil.HasStdin() {
		s := bufio.NewScanner(os.Stdin)
		for s.Scan() {
			IdentifyTarget(s.Text())
		}
	}
}

func LoadParameters() {
	// Load parameters from a file
	flagSet := goflags.NewFlagSet()
	flagSet.Marshal = true
	flagSet.SetDescription("HEDnsExtractor - A suite for hunting suspicious targets, expose domains and phishing discovery!")
	flagSet.BoolVar(&OptionCmd.Onlydomains, "only-domains", false, "show only domains")
	flagSet.BoolVar(&OptionCmd.Onlynetworks, "only-networks", false, "show only networks")
	flagSet.StringVar(&OptionCmd.Workflow, "workflow", "", "Workflow config")
	flagSet.StringVar(&OptionCmd.Target, "target", "", "IP Address or Network to query")
	flagSet.IntVar(&OptionCmd.Timeout, "timeout", 10, "Timeout in seconds")
	flagSet.BoolVar(&OptionCmd.Silent, "silent", false, "show silent output")
	flagSet.BoolVar(&OptionCmd.Verbose, "verbose", false, "show verbose output")

	flagSet.CreateGroup("configuration", "Configuration",
		flagSet.StringVar(&OptionCmd.Config, "config", DefaultConfigLocation, "flag config file"),
	)

	flagSet.CreateGroup("config", "Virustotal",
		flagSet.BoolVar(&OptionCmd.Vtscore, "vt", false, "show Virustotal score"),
		flagSet.StringVar(&OptionCmd.VtApiKey, "vt-api-key", "", "Virustotal API Key"),
		flagSet.StringVar(&OptionCmd.VtscoreValue, "vt-score", "0", "Minimum Virustotal score to show"),
	)

	if err := flagSet.Parse(); err != nil {
		gologger.Fatal().Msgf("Could not parse flags: %s\n", err)
	}

	if OptionCmd.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	} else if OptionCmd.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	} else {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	}

	if OptionCmd.Vtscore && OptionCmd.VtApiKey == "" {
		gologger.Fatal().Msgf("A Virustotal API Key is needed in config file: %s\n", DefaultConfigLocation)
	}

	// Look into target parameter to grab the IPv4s and Networks
	if OptionCmd.Target != "" {
		gologger.Verbose().Msgf("Identifying networks for %s", OptionCmd.Target)
		IdentifyTarget(OptionCmd.Target)
	}
}
