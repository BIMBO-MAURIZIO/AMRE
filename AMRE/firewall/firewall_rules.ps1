param ([String] $ips)
 
# Set-ExecutionPolicy RemoteSigned
# create an empty array
$new_ips = @()

#creation of inbound rule
if(!(Get-NetFirewallRule -DisplayName "IP_custom_block_inbound" -ErrorAction SilentlyContinue)) {
    # if the rule does not exist, create it silently and keep it disabled
    New-NetFirewallRule -DisplayName "IP_custom_block_inbound" -Direction Inbound -Action Block -Enabled False
}

#creation of outbound rule
if(!(Get-NetFirewallRule -DisplayName "IP_custom_block_outbound" -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName "IP_custom_block_outbound" -Direction Outbound -Action Block -Enabled False
}

#parse the input string (which is in the format 'ip1,ip2,ip3' ecc) and put ips into an array
foreach ($ip in ($ips -split ',')) {
    $new_ips += $ip    
}

# Add IP addresses from the array to your firewall rules
Set-NetFirewallRule -DisplayName "IP_custom_block_inbound" -Direction Inbound -Action Block -RemoteAddress $new_ips
Set-NetFirewallRule -DisplayName "IP_custom_block_outbound" -Direction Outbound -Action Block -RemoteAddress $new_ips

# Does the firewall rule contain one IP address or more?
if((Get-NetFirewallRule -DisplayName "IP_custom_block_inbound" | Get-NetFirewallAddressFilter).RemoteAddress.count -ge 1) {
	# check if the rule is enabled
	if((Get-NetFirewallRule -DisplayName "IP_custom_block_inbound").Enabled -eq "False") {
		# if the rule in disabled, enable it
		Set-NetFirewallRule -DisplayName "IP_custom_block_inbound" -Enabled True
	}
}

# Same thing as before for outbound rules
if((Get-NetFirewallRule -DisplayName "IP_custom_block_outbound" | Get-NetFirewallAddressFilter).RemoteAddress.count -ge 1) {
	if((Get-NetFirewallRule -DisplayName "IP_custom_block_outbound").Enabled -eq "False") {
		Set-NetFirewallRule -DisplayName "IP_custom_block_outbound" -Enabled True
	}
}