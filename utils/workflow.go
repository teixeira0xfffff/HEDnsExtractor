package utils

import (
	"log"
	"os"

	"github.com/projectdiscovery/gologger"
	"gopkg.in/yaml.v2"
)

type Workflow struct {
	Domains  []string `yaml:"domains"`
	Ipaddrs  []string `yaml:"ipaddrs"`
	Networks []string `yaml:"networks"`
	Regex    string   `yaml:"regex"`
}

func (c *Workflow) GetConf(filename string) *Workflow {
	yamlFile, err := os.ReadFile(filename)
	if err != nil {
		gologger.Fatal().Msgf("Could not %s\n", err)
	}

	err = yaml.Unmarshal(yamlFile, c)
	if err != nil {
		log.Fatalf("Unmarshal: %v", err)
	}
	return c
}
