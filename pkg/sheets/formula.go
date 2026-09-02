package sheets

import (
	"fmt"
	"net/url"
)

const (
	DefaultBaseURL     = "https://autsorz/l/"
	SchemePrefix       = "3" // Scheme 3 = Ed25519 Asymmetric Digital Signature
	DefaultQRServerAPI = "https://api.qrserver.com/v1/create-qr-code/"
	DefaultQRSize      = 310
	DefaultECC         = "M"
	DefaultMargin      = 1
)

// BuildFullURL appends the scheme prefix ("3") and Base64URL token to the autsorz base URL.
// Example: https://autsorz/l/3<Base64URL>
func BuildFullURL(tokenBase64URL string) string {
	return DefaultBaseURL + SchemePrefix + tokenBase64URL
}

// BuildGoogleSheetsFormula generates the Excel/Sheets formula with direct URL string.
func BuildGoogleSheetsFormula(fullURL string) string {
	return fmt.Sprintf(`=IMAGE("%s?size=%dx%d&ecc=%s&margin=%d&data=" & ENCODEURL("%s"))`,
		DefaultQRServerAPI, DefaultQRSize, DefaultQRSize, DefaultECC, DefaultMargin, fullURL)
}

// BuildGoogleSheetsCellFormula generates the Sheets formula referencing another cell (e.g. "A2").
func BuildGoogleSheetsCellFormula(cellReference string) string {
	return fmt.Sprintf(`=IMAGE("%s?size=%dx%d&ecc=%s&margin=%d&data=" & ENCODEURL(%s))`,
		DefaultQRServerAPI, DefaultQRSize, DefaultQRSize, DefaultECC, DefaultMargin, cellReference)
}

// BuildQuickChartURL returns an alternative QR code API URL (QuickChart).
func BuildQuickChartURL(fullURL string) string {
	return fmt.Sprintf(`https://quickchart.io/qr?text=%s&size=%d&ecLevel=%s&margin=%d`,
		url.QueryEscape(fullURL), DefaultQRSize, DefaultECC, DefaultMargin)
}
