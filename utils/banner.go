package utils

import (
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
)

const (
	primaryColor   = "\033[0;36m" // Cyan
	secondaryColor = "\033[0;35m" // Magenta
	reset          = "\033[0m"
)

var glitchTitle = []string{
	"██╗  ██╗███████╗██████╗ ██╗  ██╗",
	"██║  ██║██╔════╝██╔══██╗╚██╗██╔╝",
	"███████║█████╗  ██║  ██║ ╚███╔╝ ",
	"██╔══██║██╔══╝  ██║  ██║ ██╔██╗ ",
	"██║  ██║███████╗██████╔╝██╔╝ ██╗",
	"╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝  ╚═╝",
}

var subtitle = "HEDnsExtractor - HuntDownProject"

var version = "v1.0.7"

func ShowBanner() {
	displayGlitchTitle()
	fmt.Println()
	gologger.Info().Msgf("Current version: %s", version)
	gologger.Info().Msgf("Config Directory: %s", configDir)
}

func displayGlitchTitle() {
	glitchChars := "!@#$%^&*()_+-=[]{}|;:,.<>?"
	rand.Seed(time.Now().UnixNano())

	for _, line := range glitchTitle {
		glitchedLine := ""
		for _, char := range line {
			if rand.Float32() < 0.1 { // 10% chance of glitch
				glitchedLine += string(glitchChars[rand.Intn(len(glitchChars))])
			} else {
				glitchedLine += string(char)
			}
		}

		if rand.Float32() < 0.5 {
			fmt.Println(primaryColor + glitchedLine + reset)
		} else {
			fmt.Println(secondaryColor + glitchedLine + reset)
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Display subtitle
	fmt.Println(primaryColor + strings.Repeat("=", len(subtitle)) + reset)
	fmt.Println(secondaryColor + subtitle + reset)
	fmt.Println(primaryColor + strings.Repeat("=", len(subtitle)) + reset)
}
