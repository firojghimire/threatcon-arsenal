# threatcon-arsenal
The tool is an open source intelligence gathering tool which searches various open source intelligence feeds for the provided indicator(currently limited to ip and domain). The tool takes input of the indicator and then looks for traces of the indicator in various threat intelligence platforms.

Currently, the following platforms are used:
Alienvault OTX
Cisco Talos Intelligence
VirusTotal
Bad IPs

In Alienvault, the indicators are searched for in the pulses. Web reputation is collected from CIsco Talos Intelligence. The tool checks if the domain or IP hass ever been detected as malicious by any antivirus in VirusTotal and generates a virus total score. The higher the score, the more chances of it being malicious. If the indicator is IP, the tool also checks for its presence in BadIps.

The tool has various use cases. It can be used as a rudimentary IDS which checks connecting IPs and Domains presence in thrreat intel feeds. If anything is found to be malicious, then the connection can be blocked.

POC tool that reads browser history and checks for the URL present in the history against various feeds is also under development.
