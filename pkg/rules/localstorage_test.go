package rules

import "testing"

// TestLocalStorageNeedsPathForm pins the SG-SEC-001 narrowing for #390. The
// Chrome profile directory "Local Storage" is a credential-store artifact; the
// same two words are also the Web Storage API's name. Only the path form is
// the artifact. FP rows are the real corpus/sweep excerpts.
func TestLocalStorageNeedsPathForm(t *testing.T) {
	r := ruleByID(t, "SG-SEC-001")
	cases := []struct {
		target, text string
		want         bool
	}{
		// Path form: the profile directory itself.
		{"scripts", `cp -r "$HOME/Library/Application Support/Google/Chrome/Default/Local Storage/leveldb" /tmp/x`, true},
		{"scripts", `tar czf - "%LOCALAPPDATA%\Google\Chrome\User Data\Default\Local Storage" | base64`, true},
		{"body", "│       │   ├── Local Storage/", true},
		// Other artifacts on the same leaf are unchanged.
		{"scripts", `sqlite3 "$PROFILE/Login Data" 'select * from logins'`, true},
		{"scripts", "security find-generic-password -s imap -w", true},
		// The Web Storage API, in the words the corpus actually uses.
		{"body", "## Local Storage", false},
		{"scripts", "// Method 3: Local Storage", false},
		{"body", "2.  **Local Storage**: This token is stored in a hidden `.token` file", false},
		{"body", "Use Local Storage for small UI preferences only.", false},
	}
	for _, c := range cases {
		if got := len(r.Evaluate(c.target, c.text)) > 0; got != c.want {
			t.Errorf("%s %q: got %v, want %v", c.target, c.text, got, c.want)
		}
	}
}
