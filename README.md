SOC 175 - Powershell found in a request url - Possible CVE-2022-41082 exploitation.

When I examineed why the alert was triggered in the first place, there were presence of powershell word in the Http
request causes the rule with the ID SOC 175 to be triggered.

When the source IP address was search in VirusTotal, it was malicious.

The request URL was proven to be similar to CVE-2022-41082, therefore harmful.

Attacked did not succeed, the malicious IP couldnt be found on the endpoint detection or mailbox.
