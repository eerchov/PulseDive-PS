######################################################################################################
# PulseDive Lookup v0.1b by @EErchov                                                                 #
# PowerShell script that checks Cyber Threat Intel information for IPs & Domains using PulseDive API #
# Script grabs a list of IPs/Domains from input.csv file & dumps results of lookups into output.csv  #
######################################################################################################


######################################
### Configuration Settings - START ###

#Change home_dir value to define home directory for input and output .csv files
$home_dir = "C:\PulseDive-PS\"

#Register for a free account & get API key associated with your account
$pulsedive_api_key = "1212121212121212121212121212121212121212121212121212121212121212"

 #Throtle-Down Configuration
 #2 second delay between API calls to stay under <30 Calls/Min for Free PulseDive API plan
 $delay_between_calls = 0
 #1 hour pause after 500 calls/hour for Free PulseDive API plan
 $hr_pause_after = 500
 #Throtle-Down Configuration can be updated accordingly for paid plans

#This Section defines full paths for input and output .csv files. A date/time stamp added to the output.csv filename
$import_csv_location = $home_dir + "input.csv"
$cur_date = get-date
$output_csv_location = "output_" + $cur_date + ".csv"
$output_csv_location = $output_csv_location -replace " ", '_'
$output_csv_location = $output_csv_location -replace "/", '-'
$output_csv_location = $output_csv_location -replace ":", '-'
$output_csv_location = $home_dir + $output_csv_location

###  Configuration Settings - END  ###
######################################


#######################################
# Initialization of Variables - START #
$results = @()
$api_calls_cnt = 1
$url = ""
$WebResponse = ""
$x = ""
#  Initialization of Variables - END  #
#######################################

#Reading values for PulseDive API lookups from input.csv
Write-Host "Importing IPs/Domains for look up from: $import_csv_location"
Import-Csv $import_csv_location |`
    ForEach-Object {
        $IP_Domain = $_.Input.replace("[","").replace("]","")
		Write-Host "#$api_calls_cnt Looking up: " $IP_Domain
		$url = ""
		$WebResponse = ""
		$x = ""

			#Looking up Cyber Threat Intel for $IP_Domain using PulseDiveAPI
			$url = "https://pulsedive.com/api/info.php?indicator="+$IP_Domain+"&pretty=1&key="+$pulsedive_api_key
			$WebResponse = Invoke-WebRequest $url -UseBasicParsing

			#Replacement of "Country" with "country" fixes the issue with case-sensetivity @ JSON
			$x = $WebResponse -replace 'Country', 'country' | ConvertFrom-Json 
			
			#Risk
			$risk_level = $x.risk | Out-String

			#Associated Threats
			$threat_names = $x.threats.name | Out-String

			#Date Added
			$indicator_added = $x.stamp_added | Out-String

			#Last Seen/Reported
			$indicator_last_seen = $x.stamp_seen | Out-String

			#Reported Redirects
			$redirects_to = $x.redirects.to.indicator | Out-String

			#Host type
			$host_type = $x.attributes.hosttype | Out-String

			#Host ports
			$host_ports = $x.attributes.port | Out-String

			#Host protocols
			$host_protocols = $x.attributes.protocol | Out-String

			#Host technology
			$host_technology = $x.attributes.technology | Out-String

			#Host DNS
			$host_dns = $x.properties.dns | Out-String

			#Host ASN
			$host_asn = $x.properties.geo.asn | Out-String

			#Host country
			$host_country = $x.properties.geo.country | Out-String

			#Host country code
			$host_countrycode = $x.properties.geo.countrycode | Out-String

			#Host ISP
			$host_isp = $x.properties.geo.isp | Out-String

			#Host Lat
			$host_lat = $x.properties.geo.lat | Out-String

			#Host Long
			$host_long = $x.properties.geo.long | Out-String
			
			#Host http
			$host_http = $x.properties.http | Out-String

			#Host meta
			$host_meta = $x.properties.meta | Out-String

			#Host SSL
			$host_ssl = $x.properties.ssl | Out-String

			#Host WhoIs Email | to be finished later JSON & "-" issue
			#$host_whois_email = $x.properties.whois['++email'] | Out-String

			#Host WhoIs All - I was lazy to parse all that... maybe later
			#$host_whois = $x.properties.whois | Out-String

		
				#Pulling information from JSON response for output to .csv
		        $details =  [ordered] @{        
				IPs_Domains			= $IP_Domain.replace(".","[.]")
             
				#Info from PulseDive API Lookup
				risk_level = $risk_level.replace("`n"," ").replace("`r"," ")
				threat_names = $threat_names.replace("`n"," ").replace("`r"," ")

				host_country = $host_country.replace("`n"," ").replace("`r"," ")
				host_countrycode = $host_countrycode.replace("`n"," ").replace("`r"," ")
				host_lat = $host_lat.replace("`n"," ").replace("`r"," ")
				host_long = $host_long.replace("`n"," ").replace("`r"," ")
				host_asn = $host_asn.replace("`n"," ").replace("`r"," ")
				indicator_added = $indicator_added.replace("`n"," ").replace("`r"," ")
				indicator_last_seen = $indicator_last_seen.replace("`n"," ").replace("`r"," ")
				redirects_to = $redirects_to.replace("`n"," ").replace("`r"," ").replace(".","[.]")
				#host_whois_email = $host_whois_email.replace("`n"," ").replace("`r"," ")
				host_type = $host_type.replace("`n"," ").replace("`r"," ")
				host_ports = $host_ports.replace("`n"," ").replace("`r"," ")
				host_protocols = $host_protocols.replace("`n"," ").replace("`r"," ")
				host_technology = $host_technology.replace("`n"," ").replace("`r"," ")
				host_dns = $host_dns.replace("`n"," ").replace("`r"," ")

				host_isp = $host_isp.replace("`n"," ").replace("`r"," ")
				host_http = $host_http.replace("`n"," ").replace("`r"," ")
				host_meta = $host_meta.replace("`n"," ").replace("`r"," ")
				host_ssl = $host_ssl.replace("`n"," ").replace("`r"," ")
				#host_whois = $host_whois.replace("`n"," ").replace("`r"," ")
			}                           
        $results += New-Object PSObject -Property $details
		
		################################
		# Throtle-Down Section - START #
		
		#Delays between API calls to stay under per Minute limit
		Start-Sleep $delay_between_calls
		
		#Delays to stay under per Hour limit
		If ($api_calls_cnt -eq $hr_pause_after) {
			Write-Host "Script paused for 1 Hour"
			Start-Sleep 3600
			$api_calls_cnt = 0
		}
		$api_calls_cnt++
		#  Throtle-Down Section - END  #		
		################################
    }
	
#Writing results into output-DATE-TIME.csv file
Write-Host $output_csv_location
$results | export-csv -Path $output_csv_location -NoTypeInformation