package utils

import (
	"github.com/projectdiscovery/gologger"
)

var banner = `

╭╮╱╭┳━━━┳━━━╮╱╱╱╱╱╭━━━╮╱╱╭╮╱╱╱╱╱╱╱╱╭╮
┃┃╱┃┃╭━━┻╮╭╮┃╱╱╱╱╱┃╭━━╯╱╭╯╰╮╱╱╱╱╱╱╭╯╰╮
┃╰━╯┃╰━━╮┃┃┃┣━╮╭━━┫╰━━┳╮┣╮╭╋━┳━━┳━┻╮╭╋━━┳━╮
┃╭━╮┃╭━━╯┃┃┃┃╭╮┫━━┫╭━━┻╋╋┫┃┃╭┫╭╮┃╭━┫┃┃╭╮┃╭╯
┃┃╱┃┃╰━━┳╯╰╯┃┃┃┣━━┃╰━━┳╋╋┫╰┫┃┃╭╮┃╰━┫╰┫╰╯┃┃
╰╯╱╰┻━━━┻━━━┻╯╰┻━━┻━━━┻╯╰┻━┻╯╰╯╰┻━━┻━┻━━┻╯
`

var version = "v1.0.5"

func ShowBanner() {
	gologger.Print().Msgf("%s\n", banner)
	gologger.Info().Msgf("Current hednsextractor version %s", version)
	gologger.Info().Msgf("HEDnsExtractor Config Directory: %s", configDir)
}
