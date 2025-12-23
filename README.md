# Email Sender Spoofing via Header Manipulation and Whitespace Injection Bypassing Spoofing Protections

A vulnerability exists in the way Microsoft Exchange Online and the outlook client parse and display the header in incoming emails. By crafting a specifically malformed SMTP transaction using tools like swaks , an attacker can bypass traditional spoofing detection (SPF alignment checks) and visual security indicators.

The root cause appears to be a discrepancy in how the Email Gateway and the Mail Client handle whitespace or specific characters within the header (e.g., ). Specifically:Fromadmin@ gmail.com

Maybe The gateway fails to correctly extract the domain for comparison against internal protected domains when a space is injected.

The gmail client renders the forged "Display Name" and "Forged Email" while failing to show "External" or "Identity Unverified" warnings, leading users to believe the email originated from a trusted internal or official source.

Impact
High-Scale Phishing: Attackers can impersonate high-level executives (CEOs), IT departments, or partners to steal credentials.

Internal Fraud: Forging internal communications to request wire transfers or sensitive data.

Evasion of Security Filters: Since the gateway misidentifies the sender domain due to the malformed header, the email bypasses the "Sender Spoofed" rejection logic.

Reproduction Steps
Prerequisites:

A third-party SMTP server or an SMTP relay service.

The toolkit.swaks

Steps:

Construct a malformed email: Use a "Display Name" that includes a forged email address and inject a space within the domain part to confuse the parser.

Execute the attack via CLI:

Bash

swaks --to [target_user]@gmail.com \
      --from [attacker]@attacker-domain.com \
      --h-From: 'IT Support <admin@ gmail.com>' \
      --ehlo gmail.com \
      --server [your_smtp_server] \
      -p 25 -au [username] -ap [password] \
      --body "Please reset your password at: http://malicious-link.com"
Observation:

Check the recipient's gmail Inbox.

Observe that the sender is displayed as or the provided Display Name without "External" tags or "Unverified" warnings.admin@gmail.com

The gateway allows the mail through because (with a space) does not trigger the strict string-match for the protected domain.admin@ gmail.comgmail.com
