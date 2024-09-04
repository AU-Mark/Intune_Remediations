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

$DisabledServices = @()

Try {
    ForEach ($Service in $ServicesToDisable) { 
        Try {
            If ((Get-Service $Service -ErrorAction Stop).StartType -ne "Disabled") {
                Set-Service -Name $Service -StartupType Disabled
                If ((Get-Service $Service).Status -eq 'Running') {
                    Stop-Service -Name $Service -Force
                }
                $DisabledServices += $Service
            } 
        } Catch {
            Continue
        }
    }

    If ($DisabledServices.Count -ge 1) {
        Write-Output "These services were stopped and disabled: $($DisabledServices -join ',')"
        Exit 0
    } Else {
        Write-Output "All defined services are disabled"
        Exit 0
    }
} Catch {
    Write-Output "An error occured - Err Line: $($_.InvocationInfo.ScriptLineNumber) Err Name: $($_.Exception.GetType().FullName) Err Msg: $($_.Exception.Message)"
    Exit 1
}