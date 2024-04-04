package utils

import (
	"path/filepath"

	folderutil "github.com/projectdiscovery/utils/folder"
)

type Result struct {
	IPAddr  string
	PTR     string
	Domain  string
	VtScore uint64
}

var (
	configDir             = folderutil.AppConfigDirOrDefault(".", "hednsextractor")
	DefaultConfigLocation = filepath.Join(configDir, "config.yaml")

	Hosts    []string
	Networks []string
	Domains  []string
)

var Results = make(map[string]Result)
