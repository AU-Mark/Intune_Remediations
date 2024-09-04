$ServicesToDisable = (
    "CscService",       # Offline Files
    "icssvc",           # Windows Mobile Hotspot
    "ftpsvc",           # Windows FTP
    "IISADMIN",         # IIS Admin
    "irmon",            # Infared (IrDA) Monitor
    "RemoteAccess",     # Routing and Remote Access
    "RpcLocator",       # Remote Procedure Call (RPC) Locator
    "SharedAccess",     # Internet Connection Sharing
    "simptcp",          # Simple TCP/IP Services
    "SSDPSRV",          # SSDP Discovery
    "sshd",             # OpenSSH Server
    "upnphost",         # UPnP Device Host
    "W3SVC",            # IIS World Wide Web Publishing Service
    "WMPNetworkSvc",    # Windows Media Player Network Sharing
    "WMSVC"             # Web Management Service
    )

$EnabledServices = @()

ForEach ($Service in $ServicesToDisable) { 
    Try {
        If ((Get-Service $Service -ErrorAction Stop).StartType -ne "Disabled") { 
            $EnabledServices += $Service
        } 
    } Catch {
        Continue
    }
}

If ($EnabledServices.Count -ge 1) {
    Write-Output "These services were not disabled: $($EnabledServices -join ',')"
    Exit 1
} Else {
    Write-Output "All defined services are disabled"
    Exit 0
}