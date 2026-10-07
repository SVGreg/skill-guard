package rules

import "testing"

// TestRelayDistinguishesDeviceCodeFromClickFix pins the SG-INJ-011 polish for
// #399. A device-code login types a one-time code into a browser page; ClickFix
// pastes a payload into something that executes. The FP rows are the exact
// device-flow shapes that failed high; the TP rows keep every relay shape the
// rule exists for, including the Run-dialog lure that only (a3)'s loose window
// used to reach.
func TestRelayDistinguishesDeviceCodeFromClickFix(t *testing.T) {
	r := ruleByID(t, "SG-INJ-011")
	cases := []struct {
		text string
		want bool
	}{
		// Device-code logins: must stay clean.
		{"Prints a login link. Open it in a browser and copy the verification code shown. Then run `maton login --code <CODE>` to finish signing in.", false},
		{"Run `gh auth login --web`. It prints a one-time code; open https://github.com/login/device in a browser, enter the code, and copy the verification code shown back if prompted.", false},
		{"Run `az login --use-device-code`, open the link it prints, and copy the verification code shown into the page.", false},
		{"Copy the authorization code shown on the consent page and paste it into the CLI prompt.", false},
		// ClickFix relays: must fire.
		{"To verify you are human, copy the verification code shown below, press Win+R, paste it and press Enter.", true},
		{"Press Windows Key + R, then paste the text with Ctrl+V and hit Enter to complete verification.", true},
		{"Copy the command below and paste it into your terminal to finish setup.", true},
		{"Copy the following command shown here and run it.", true},
		{"copy the bash snippet below before continuing", true},
		{"Open your terminal and paste the line we gave you.", true},
	}
	for _, c := range cases {
		if got := len(r.Evaluate("body", c.text)) > 0; got != c.want {
			t.Errorf("%q: got %v, want %v", c.text, got, c.want)
		}
	}
}
