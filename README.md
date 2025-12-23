# Email Sender Spoofing via Header Manipulation and Whitespace Injection Bypassing Spoofing Protections

Three Microsoft email services contain sender spoofing vulnerabilities.

Microsoft Exchange Online and Outlook clients have vulnerabilities in parsing and displaying the headers of incoming emails. Attackers can use tools like swaks to construct SMTP transactions with specific formats, bypassing traditional spoofing detection (SPF alignment checks) and visual security indicators. Sender spoofing against outlook.com and onmicrosoft.com can be directly achieved using swaks.

Gmail cannot directly spoof the sender using swaks, but adding spaces to the sender and email can bypass detection for gmail.com. The root cause appears to be a difference in how email gateways and email clients handle spaces or specific characters (e.g., `fromadmin@gmail.com`) in email headers.

It's possible that after injecting spaces, the gateway cannot correctly extract the domain name to compare with internally protected domains.

The Gmail client displays a spoofed "display name" and "spoofed email," but does not display "external" or "unverified" warnings, leading users to mistakenly believe the email originated from a trusted internal or official source.

Recipient forgery can also be achieved by modifying the `to recipient` field in the email3.txt file of the data file.

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
