# PulseDive-Lookup.ps1 v0.1b
PowerShell script for bulk Cyber Threat Intel information lookups for IPs &amp; Domains using PulseDive API

# Overview

PulseDive (pulsedive.com / @pulsedive) is a free Cyber Threat Intelligence platform that: 

    - Aggregates IOCs from its’ community members and OSINT feeds

    - Enriches IOCs by performing WHOIS requests and active DNS resolutions

    - Probes IOCs by sending HTTP GET requests to collect additional valuable data like HTTP headers, SSL certificate information, and redirects

PulseDive offers great web-based interface for Cyber Threat Intel and IT Security analysts. PulseDive also offers APIs that can be used for integrations with SIEM tools and etc.

PulseDive-Lookup.ps1 is a PowerShell script that leverages PulseDive API for bulk IPs/Domains lookups.

# How It Works

1.	Save list of IPs/Domains in the Input.csv file. Square brackets around dots are optional.
2.	Execute “PulseDive-Lookup.ps1” PowerShell script
3.	Script will grab all IOCs from Input.csv one-by-on and will look them up using PulseDive API. The results will be stored in Output_[DATE]_[TIME].csv file

# Configurations
1.	Register for a free account on PulseDive.com and get API key associated with your profile. Update $pulsedive_api_key variable in PulseDive-Lookup.ps1 with your key

2.	Update variable $home_dir to define location where Input and Output .csv files will be located

3.	PulseDive’s Free Tier API has 30 request per min & 500 request per hour limitations
Default values of variables $delay_between_calls & $hr_pause_after throttle down speed of lookups to stay within the free limits of PulseDive API. Update those variables accordingly for paid plans.

4.	If you’ll get errors related to “Invoke-WebRequest”, run the following commands:
        #PS C:\> $AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
        #PS C:\> [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
        #PS C:\> (Invoke-WebRequest -Uri "https://idp.safenames.com/").StatusCode

# Point Of Contact
Evgueni Erchov

Kivu Consulting, Inc | Cyber Investigations

E: EErchov@KivuConsulting.com | T: @EErchov 
