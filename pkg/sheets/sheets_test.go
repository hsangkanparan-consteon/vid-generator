package sheets

import (
	"strings"
	"testing"
)

func TestSheetsFormulas(t *testing.T) {
	token := "AQEB_test_token"
	fullURL := BuildFullURL(token)

	expectedURL := "https://autsorz/l/3AQEB_test_token"
	if fullURL != expectedURL {
		t.Errorf("expected full URL %s, got %s", expectedURL, fullURL)
	}

	formula := BuildGoogleSheetsFormula(fullURL)
	if !strings.HasPrefix(formula, `=IMAGE("https://api.qrserver.com/v1/create-qr-code/`) {
		t.Errorf("unexpected formula format: %s", formula)
	}
	if !strings.Contains(formula, "ENCODEURL(\""+expectedURL+"\")") {
		t.Errorf("formula does not contain escaped URL: %s", formula)
	}

	cellFormula := BuildGoogleSheetsCellFormula("A2")
	if !strings.Contains(cellFormula, "ENCODEURL(A2)") {
		t.Errorf("cell formula missing ENCODEURL(A2): %s", cellFormula)
	}

	quickChart := BuildQuickChartURL(fullURL)
	if !strings.HasPrefix(quickChart, "https://quickchart.io/qr?") {
		t.Errorf("unexpected quickchart format: %s", quickChart)
	}
}
