package ui

import (
	"fmt"
	"os"
	"strings"

	"dnshunt/pkg/dns"
)

func PrintBanner() {
	banner := CBCyan + `
   ██████╗ ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗
   ██╔══██╗████╗  ██║██╔════╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝
   ██║  ██║██╔██╗ ██║███████╗███████║██║   ██║██╔██╗ ██║   ██║   
   ██║  ██║██║╚██╗██║╚════██║██╔══██║██║   ██║██║╚██╗██║   ██║   
   ██████╔╝██║ ╚████║███████║██║  ██║╚██████╔╝██║ ╚████║   ██║   
   ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ` + CReset + `
` + CBMag + `         ⚡ Fast Concurrent DNS Resolver ⚡` + CReset + `
` + CBYellow + `              Made with ♥ by CodejaVu Team` + CReset + `
` + CDim + `   ─────────────────────────────────────────────────────` + CReset + `
`
	fmt.Println(banner)
}

func PrintHelp() {
	PrintBanner()
	fmt.Printf("%sUSAGE:%s\n  dnshunt [options]\n\n", CBold+CBGreen, CReset)
	fmt.Printf("%sOPTIONS:%s\n", CBold+CBGreen, CReset)
	opts := [][]string{
		{"-r", "<file>", "File containing DNS resolver IPs"},
		{"-R", "<list>", "Comma-separated resolver IPs"},
		{"-l", "<file>", "Target list file"},
		{"-t", "<type>", "DNS record type (A, AAAA, CNAME, TXT, MX, etc.)"},
		{"-c", "<int>", "Concurrency level (default: 100)"},
		{"-timeout", "<ms>", "Query timeout in ms (default: 3000)"},
		{"-rc", "<int>", "Resolvers per target (default: 5)"},
		{"-tcp", "", "Use TCP instead of UDP"},
		{"-v", "", "Verbose live printing"},
		{"-o", "<file>", "Output file (.json or .txt)"},
		{"-h", "", "Show help"},
	}
	for _, o := range opts {
		fmt.Printf("  %s%-10s%s %s%-10s%s %s\n", CBCyan, o[0], CReset, CYellow, o[1], CReset, o[2])
	}
}

func PrintResultLive(res dns.Result, verbose bool) {
	if !verbose {
		return
	}
	fmt.Fprint(os.Stderr, "\r\033[K")
	if res.Success {
		fmt.Printf("%s[+]%s %s%-40s%s %s→%s %s%s%s\n",
			CBGreen, CReset, CBold, res.Target, CReset, CDim, CReset, CBCyan, strings.Join(res.Answers, ", "), CReset)
	} else {
		reason := "no answer"
		if len(res.Errors) > 0 {
			reason = res.Errors[0]
		}
		fmt.Printf("%s[-]%s %s%-40s%s %s(%s)%s\n", CBRed, CReset, CDim, res.Target, CReset, CRed, reason, CReset)
	}
}