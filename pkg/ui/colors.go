package ui

var (
	CReset   = "\033[0m"
	CBold    = "\033[1m"
	CDim     = "\033[2m"
	CRed     = "\033[31m"
	CGreen   = "\033[32m"
	CYellow  = "\033[33m"
	CBlue    = "\033[34m"
	CMagenta = "\033[35m"
	CCyan    = "\033[36m"
	CBRed    = "\033[91m"
	CBGreen  = "\033[92m"
	CBYellow = "\033[93m"
	CBBlue   = "\033[94m"
	CBMag    = "\033[95m"
	CBCyan   = "\033[96m"
)

func DisableColors() {
	CReset, CBold, CDim = "", "", ""
	CRed, CGreen, CYellow, CBlue, CMagenta, CCyan = "", "", "", "", "", ""
	CBRed, CBGreen, CBYellow, CBBlue, CBMag, CBCyan = "", "", "", "", "", ""
}
