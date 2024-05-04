package utils

type options struct {
	Silent       bool
	Verbose      bool
	Onlydomains  bool
	Onlynetworks bool
	Workflow     string
	Vtscore      bool
	VtscoreValue string
	VtApiKey     string
	Target       string
	Timeout      int
	Domain       string
	Config       string
}

var OptionCmd = &options{}
