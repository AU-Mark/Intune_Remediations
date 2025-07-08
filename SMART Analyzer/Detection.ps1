<#
.SYNOPSIS
    SMART Disk Health Detection Script for Intune Remediation with Teams Notifications

.DESCRIPTION
    This script analyzes HDD, SSD, and NVMe SMART attributes to detect failing drives and sends
    detailed notifications to Microsoft Teams via webhook using modern Adaptive Cards v1.5.
    Designed as an Intune detection script that exits with code 1 when failures are detected
    and code 0 when all drives are healthy.

.NOTES
    Version: 2.0
    Author: Expert PowerShell Automation Engineer
    Last Updated: 07/07/2025
    PowerShell Version: 5.1
    
    This script will:
    1. Scan all physical disks for SMART health status with drive type detection
    2. Analyze critical SMART attributes for failure prediction using latest industry standards
    3. Gather comprehensive device and disk information
    4. Calculate estimated time remaining for failing drives (where possible)
    5. Send modern Teams notifications with detailed diagnostic information
    6. Exit with appropriate codes for Intune remediation logic
    
    Improvements in v2.0:
    - NVMe and SSD detection patterns
    - Updated SMART thresholds based on 2024/2025 research
    - Better handling of modern drive naming conventions
    - Improved error handling and logging
    - Teams notification formatting

.EXAMPLE
    This script is typically deployed as an Intune detection script and should not be run manually.

.OUTPUTS
    Exit Code 0: All drives are healthy
    Exit Code 1: One or more drives show signs of failure (triggers remediation workflow)
#>

#########################################################################################################################
#                                                 Configuration Variables                                                #
#########################################################################################################################

# Teams webhook configuration - Set to $false to disable notifications
$script:SendTeamsNotification = $true
$script:WebhookUrl = 'https://prod-147.westus.logic.azure.com:443/workflows/0dae2894cb0842ce8177d6429f4858cd/triggers/manual/paths/invoke?api-version=2016-06-01&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=7F4x1goQD31VNd1wRbqXoufblPvaK3xyv0Iap32iHag'

# smartctl configuration - Add after the existing configuration variables
$script:SmartctlEnabled = $true
$script:SmartctlCachePath = "$env:TEMP\smartctl_cache"
$script:SmartctlExecutable = "$script:SmartctlCachePath\smartctl.exe"
$script:GitHubReleasesUrl = 'https://api.github.com/repos/smartmontools/smartmontools/releases/latest'

# SMART monitoring configuration
$script:MaxRetryAttempts = 3
$script:RetryDelaySeconds = 2

# critical SMART attribute thresholds based on research from Google, Backblaze, and industry studies (2024-2025)
$script:CriticalThresholds = @{
    # Attributes that indicate imminent failure - ANY value > 0 is critical
    'ReallocatedSectors' = @{ Critical = 0; Warning = -1; AttributeId = 5 }           # Any reallocated sectors indicate 20-60x higher failure risk
    'UncorrectableSectors' = @{ Critical = 0; Warning = -1; AttributeId = 198 }      # Any uncorrectable sectors are critical
    'PendingSectors' = @{ Critical = 0; Warning = -1; AttributeId = 197 }            # Sectors awaiting reallocation
    'OfflineUncorrectable' = @{ Critical = 0; Warning = -1; AttributeId = 196 }      # Offline uncorrectable sectors
    'ReallocationEvents' = @{ Critical = 10; Warning = 1; AttributeId = 196 }        # Number of reallocation attempts
    
    # Attributes with warning thresholds (updated for 2025)
    'PowerOnHours' = @{ Critical = 43800; Warning = 26280; AttributeId = 9 }         # >5 years critical, >3 years warning
    'PowerCycleCount' = @{ Critical = 10000; Warning = 5000; AttributeId = 12 }      # Excessive power cycles
    'Temperature' = @{ Critical = 70; Warning = 60; AttributeId = 194 }              # Updated temperature thresholds for modern drives
    'CommandTimeout' = @{ Critical = 100; Warning = 10; AttributeId = 188 }          # Command timeouts
    'HighFlyWrites' = @{ Critical = 100; Warning = 10; AttributeId = 189 }           # Head flying height errors
    
    # SSD/NVMe specific thresholds
    'WearLevelingCount' = @{ Critical = 10; Warning = 25; AttributeId = 177 }        # SSD wear leveling
    'UsedReservedBlocks' = @{ Critical = 90; Warning = 75; AttributeId = 170 }       # Used reserved blocks percentage
    'ProgramFailCount' = @{ Critical = 100; Warning = 10; AttributeId = 171 }        # Program failures
    'EraseFailCount' = @{ Critical = 100; Warning = 10; AttributeId = 172 }          # Erase failures
    'WearRange' = @{ Critical = 1000; Warning = 500; AttributeId = 233 }             # Wear range delta
}

# smartctl SMART attribute name mapping to our human-readable names
$script:SmartctlAttributeMapping = @{
    # Critical attributes (any value > 0 is critical for these)
    'Reallocated_Sector_Ct' = 'ReallocatedSectors'
    'Offline_Uncorrectable' = 'UncorrectableSectors'
    'Current_Pending_Sector' = 'PendingSectors'
    'Reallocated_Event_Count' = 'ReallocationEvents'
    
    # Attributes with thresholds
    'Power_On_Hours' = 'PowerOnHours'
    'Power_Cycle_Count' = 'PowerCycleCount'
    'Temperature_Celsius' = 'Temperature'
    'Airflow_Temperature_Cel' = 'Temperature'
    'Command_Timeout' = 'CommandTimeout'
    'High_Fly_Writes' = 'HighFlyWrites'
    
    # SSD/NVMe specific attributes
    'Wear_Leveling_Count' = 'WearLevelingCount'
    'Used_Rsvd_Blk_Cnt_Tot' = 'UsedReservedBlocks'
    'Program_Fail_Cnt_Total' = 'ProgramFailCount'
    'Erase_Fail_Count_Total' = 'EraseFailCount'
    'Wear_Range_Delta' = 'WearRange'
}

# Logging configuration
$script:LogName = 'SMART_Detection'
$script:LogPath = "$env:TEMP\$($script:LogName).log"

#########################################################################################################################
#                                                   Logging Functions                                                   #
#########################################################################################################################

Function Write-Log {
    <#
    .SYNOPSIS
        Writes timestamped log entries with different severity levels.
        
    .DESCRIPTION
        This function provides structured logging with timestamp, log level, and message formatting
        optimized for troubleshooting and audit trails in enterprise environments.
        
    .PARAMETER LogLevel
        Severity level: SUCCESS, INFO, WARNING, ERROR
        
    .PARAMETER Message
        Log message content to write
        
    .EXAMPLE
        Write-Log -LogLevel 'INFO' -Message 'Starting SMART analysis'
        
    .NOTES
        Logs are written to both console and file for comprehensive monitoring.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('SUCCESS', 'INFO', 'WARNING', 'ERROR')]
        [String]$LogLevel,
        
        [Parameter(Mandatory = $true)]
        [String]$Message
    )
    
    Try {
        $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        $logEntry = "[$timestamp] [$LogLevel] $Message"
        
        # Write to console with color coding
        Switch ($LogLevel) {
            'SUCCESS' { Write-Host $logEntry -ForegroundColor Green }
            'INFO' { Write-Host $logEntry -ForegroundColor Cyan }
            'WARNING' { Write-Host $logEntry -ForegroundColor Yellow }
            'ERROR' { Write-Host $logEntry -ForegroundColor Red }
        }
        
        # Write to log file
        Add-Content -Path $script:LogPath -Value $logEntry -ErrorAction SilentlyContinue
        
    } Catch {
        Write-Warning "Failed to write log entry: $($_.Exception.Message)"
    }
}

Function Invoke-OperationWithRetry {
    <#
    .SYNOPSIS
        Executes operations with retry logic and exponential backoff.
        
    .DESCRIPTION
        This function provides robust retry mechanisms for potentially unreliable operations
        such as WMI queries and network requests, implementing best practices for fault tolerance.
        
    .PARAMETER ScriptBlock
        Script block containing the operation to execute
        
    .PARAMETER OperationDescription
        Human-readable description of the operation for logging
        
    .PARAMETER MaxAttempts
        Maximum number of retry attempts
        
    .EXAMPLE
        Invoke-OperationWithRetry -ScriptBlock { Get-CimInstance Win32_DiskDrive } -OperationDescription 'Disk enumeration'
        
    .NOTES
        Uses exponential backoff to avoid overwhelming systems during transient failures.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [ScriptBlock]$ScriptBlock,
        
        [Parameter(Mandatory = $true)]
        [String]$OperationDescription,
        
        [Parameter(Mandatory = $false)]
        [Int]$MaxAttempts = $script:MaxRetryAttempts
    )
    
    For ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        Try {
            Write-Log -LogLevel 'INFO' -Message "Executing $OperationDescription (attempt $attempt of $MaxAttempts)"
            $result = & $ScriptBlock
            Write-Log -LogLevel 'SUCCESS' -Message "$OperationDescription completed successfully"
            Return $result
            
        } Catch {
            $errorMessage = $_.Exception.Message
            Write-Log -LogLevel 'WARNING' -Message "$OperationDescription failed on attempt $attempt`: $errorMessage"
            
            If ($attempt -lt $MaxAttempts) {
                $delaySeconds = $script:RetryDelaySeconds * [Math]::Pow(2, ($attempt - 1))
                Write-Log -LogLevel 'INFO' -Message "Waiting $delaySeconds seconds before retry..."
                Start-Sleep -Seconds $delaySeconds
            } Else {
                Write-Log -LogLevel 'ERROR' -Message "$OperationDescription failed after $MaxAttempts attempts"
                Throw "Operation failed after $MaxAttempts attempts: $errorMessage"
            }
        }
    }
}

#########################################################################################################################
#                                              SMART Analysis Functions                                                 #
#########################################################################################################################

Function Get-SystemInformation {
    <#
    .SYNOPSIS
        Gathers comprehensive system information for device identification.
        
    .DESCRIPTION
        This function collects detailed system information including hardware details,
        OS version, and system configuration to provide context for disk health alerts.
        
    .OUTPUTS
        Hashtable containing system information
        
    .EXAMPLE
        $systemInfo = Get-SystemInformation
        
    .NOTES
        Optimized for enterprise environments with error handling for missing WMI data.
    #>
    [CmdletBinding()]
    Param()
    
    Try {
        Write-Log -LogLevel 'INFO' -Message 'Gathering system information for device identification'
        
        $systemInfo = @{}
        
        # Get computer system information
        $computerSystem = Invoke-OperationWithRetry -ScriptBlock {
            Get-CimInstance -ClassName 'Win32_ComputerSystem' -ErrorAction Stop
        } -OperationDescription 'Computer system information retrieval'
        
        # Get operating system information
        $operatingSystem = Invoke-OperationWithRetry -ScriptBlock {
            Get-CimInstance -ClassName 'Win32_OperatingSystem' -ErrorAction Stop
        } -OperationDescription 'Operating system information retrieval'
        
        # Get BIOS information
        $biosInfo = Invoke-OperationWithRetry -ScriptBlock {
            Get-CimInstance -ClassName 'Win32_BIOS' -ErrorAction Stop
        } -OperationDescription 'BIOS information retrieval'
        
        # Populate system information hashtable
        $systemInfo['ComputerName'] = $env:COMPUTERNAME
        $systemInfo['Domain'] = If ($computerSystem.Domain) { $computerSystem.Domain } Else { 'WORKGROUP' }
        $systemInfo['Manufacturer'] = If ($computerSystem.Manufacturer) { $computerSystem.Manufacturer } Else { 'Unknown' }
        $systemInfo['Model'] = If ($computerSystem.Model) { $computerSystem.Model } Else { 'Unknown' }
        $systemInfo['TotalPhysicalMemoryGB'] = [Math]::Round($computerSystem.TotalPhysicalMemory / 1GB, 2)
        $systemInfo['OSName'] = If ($operatingSystem.Caption) { $operatingSystem.Caption } Else { 'Unknown OS' }
        $systemInfo['OSVersion'] = If ($operatingSystem.Version) { $operatingSystem.Version } Else { 'Unknown' }
        $systemInfo['OSArchitecture'] = If ($operatingSystem.OSArchitecture) { $operatingSystem.OSArchitecture } Else { 'Unknown' }
        $systemInfo['LastBootTime'] = If ($operatingSystem.LastBootUpTime) { 
            $operatingSystem.LastBootUpTime.ToString('yyyy-MM-dd HH:mm:ss') 
        } Else { 'Unknown' }
        $systemInfo['BIOSVersion'] = If ($biosInfo.SMBIOSBIOSVersion) { $biosInfo.SMBIOSBIOSVersion } Else { 'Unknown' }
        $systemInfo['SerialNumber'] = If ($biosInfo.SerialNumber) { $biosInfo.SerialNumber } Else { 'Unknown' }
        
        Write-Log -LogLevel 'SUCCESS' -Message "System information gathered successfully for $($systemInfo['ComputerName'])"
        Return $systemInfo
        
    } Catch {
        Write-Log -LogLevel 'ERROR' -Message "Failed to gather system information: $($_.Exception.Message)"
        # Return minimal system info as fallback
        Return @{
            'ComputerName' = $env:COMPUTERNAME
            'Domain' = 'Unknown'
            'Manufacturer' = 'Unknown'
            'Model' = 'Unknown'
            'TotalPhysicalMemoryGB' = 0
            'OSName' = 'Unknown'
            'OSVersion' = 'Unknown'
            'OSArchitecture' = 'Unknown'
            'LastBootTime' = 'Unknown'
            'BIOSVersion' = 'Unknown'
            'SerialNumber' = 'Unknown'
        }
    }
}

Function Get-PhysicalDiskInformation {
    <#
    .SYNOPSIS
        Retrieves detailed information about all physical disks in the system.
        
    .DESCRIPTION
        This function enumerates all physical disks and gathers comprehensive information
        including make, model, serial number, capacity, interface type, and health status.
        
    .OUTPUTS
        Array of hashtables containing disk information
        
    .EXAMPLE
        $disks = Get-PhysicalDiskInformation
        
    .NOTES
        Uses multiple WMI classes to gather comprehensive disk information with fallback handling.
    #>
    [CmdletBinding()]
    Param()
    
    Try {
        Write-Log -LogLevel 'INFO' -Message 'Enumerating physical disks and gathering detailed information'
        
        $diskList = [System.Collections.Generic.List[PSObject]]::new()
        
        # Get physical disk information from Win32_DiskDrive
        $physicalDisks = Invoke-OperationWithRetry -ScriptBlock {
            Get-CimInstance -ClassName 'Win32_DiskDrive' -ErrorAction Stop | Where-Object { 
                $_.MediaType -eq 'Fixed hard disk media' -and $_.Size -gt 0 
            }
        } -OperationDescription 'Physical disk enumeration'
        
        ForEach ($disk in $physicalDisks) {
            Try {
                Write-Log -LogLevel 'INFO' -Message "Processing disk: $($disk.Model)"
                
                $diskInfo = @{
                    'DiskIndex' = $disk.Index
                    'DeviceID' = $disk.DeviceID
                    'Model' = If ($disk.Model) { $disk.Model.Trim() } Else { 'Unknown Model' }
                    'Manufacturer' = If ($disk.Manufacturer) { $disk.Manufacturer.Trim() } Else { 'Unknown Manufacturer' }
                    'SerialNumber' = If ($disk.SerialNumber) { $disk.SerialNumber.Trim() } Else { 'Unknown Serial' }
                    'SizeGB' = If ($disk.Size) { [Math]::Round($disk.Size / 1GB, 2) } Else { 0 }
                    'InterfaceType' = If ($disk.InterfaceType) { $disk.InterfaceType } Else { 'Unknown Interface' }
                    'MediaType' = If ($disk.MediaType) { $disk.MediaType } Else { 'Unknown Media' }
                    'Status' = If ($disk.Status) { $disk.Status } Else { 'Unknown Status' }
                }
                
                # Try to get additional information from Win32_PhysicalMedia
                Try {
                    $physicalMedia = Get-CimInstance -ClassName 'Win32_PhysicalMedia' -Filter "Tag='$($disk.DeviceID)'" -ErrorAction SilentlyContinue
                    If ($physicalMedia -and $physicalMedia.SerialNumber) {
                        $diskInfo['SerialNumber'] = $physicalMedia.SerialNumber.Trim()
                    }
                } Catch {
                    Write-Log -LogLevel 'WARNING' -Message "Could not retrieve physical media info for $($disk.DeviceID)"
                }
                
                # Determine disk type (SSD vs HDD vs NVMe) with detection
                $diskInfo['DriveType'] = Get-DriveType -Model $diskInfo['Model'] -Manufacturer $diskInfo['Manufacturer'] -InterfaceType $diskInfo['InterfaceType']
                
                $diskList.Add([PSCustomObject]$diskInfo)
                Write-Log -LogLevel 'SUCCESS' -Message "Successfully processed disk: $($diskInfo['Model']) - Type: $($diskInfo['DriveType'])"
                
            } Catch {
                Write-Log -LogLevel 'ERROR' -Message "Failed to process disk $($disk.DeviceID): $($_.Exception.Message)"
            }
        }
        
        Write-Log -LogLevel 'SUCCESS' -Message "Successfully enumerated $($diskList.Count) physical disks"
        Return $diskList.ToArray()
        
    } Catch {
        Write-Log -LogLevel 'ERROR' -Message "Failed to enumerate physical disks: $($_.Exception.Message)"
        Return @()
    }
}

Function Get-DriveType {
    <#
    .SYNOPSIS
        function to determine if a drive is SSD, NVMe, or HDD based on comprehensive pattern matching.
        
    .DESCRIPTION
        This function analyzes drive model, manufacturer strings, and interface type to classify
        drives as SSD, NVMe, HDD, or Unknown using extensive naming conventions and patterns
        based on 2024-2025 drive naming standards.
        
    .PARAMETER Model
        Drive model string
        
    .PARAMETER Manufacturer
        Drive manufacturer string
        
    .PARAMETER InterfaceType
        Drive interface type (if available)
        
    .OUTPUTS
        String indicating drive type (NVMe, SSD, HDD, or Unknown)
        
    .EXAMPLE
        $driveType = Get-DriveType -Model 'SAMSUNG MZVL21T0HDLU-00BH1' -Manufacturer 'Samsung' -InterfaceType 'SCSI'
        
    .NOTES
        with modern NVMe naming patterns and comprehensive manufacturer-specific patterns.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [String]$Model,
        
        [Parameter(Mandatory = $true)]
        [String]$Manufacturer,
        
        [Parameter(Mandatory = $false)]
        [String]$InterfaceType = ''
    )
    
    $combinedString = "$Model $Manufacturer $InterfaceType".ToUpper()
    
    # NVMe patterns based on 2024-2025 drive naming conventions
    $nvmeIndicators = @(
        'NVME', 'MZVL', 'MZVK', 'MZQL', 'MZPLL', 'MZQLB',  # Samsung NVMe patterns
        'WDS\d+G\d+X\d+', 'WD_BLACK SN\d+', 'WDS\d+G\d+X\d+-\w+',  # WD NVMe patterns
        'CT\d+P\d+SSD\d+', 'CT\d+P\d+NTC\d+',  # Crucial NVMe patterns
        'INTEL SSDPEK\w+', 'INTEL SSDPE\w+', 'OPTANE',  # Intel NVMe patterns
        'CORSAIR MP\d+', 'FORCE MP\d+',  # Corsair NVMe patterns
        'KINGSTON SA\d+M\d+', 'KINGSTON NV\d+',  # Kingston NVMe patterns
        'SAMSUNG PM\d+', 'SAMSUNG 9\d+\w+ NVMe',  # Samsung enterprise NVMe
        'SEAGATE FIRECUDA\d+', 'ST\d+NM\d+',  # Seagate NVMe patterns
        'ADATA XPG', 'XPG GAMMIX', 'ADATA SX\d+NP',  # ADATA NVMe patterns
        'GIGABYTE GP-GSM\d+', 'AORUS NVMe',  # Gigabyte NVMe patterns
        'SK HYNIX', 'HYNIX',  # SK Hynix patterns
        'PHISON E\d+', 'SILICON POWER P\d+A\d+',  # Other NVMe patterns
        'KIOXIA EXCERIA', 'TOSHIBA KXG\d+',  # Kioxia/Toshiba NVMe patterns
        'MICRON \d+MTFD\w+', 'CRUCIAL P\d+'  # Micron/Crucial NVMe patterns
    )
    
    # SSD patterns
    $ssdIndicators = @(
        'SSD', 'SOLID STATE', 'FLASH', 'EVO', 'PRO', 'ULTRA',
        'MZ-\w+', 'SAMSUNG 8\d+', 'SAMSUNG 9\d+ SSD',  # Samsung SSD patterns
        'WDS\d+G\d+B\d+A', 'WD BLUE', 'WD GREEN', 'WD RED SA',  # WD SSD patterns
        'CT\d+MX\d+', 'CT\d+BX\d+', 'CRUCIAL MX\d+', 'CRUCIAL BX\d+',  # Crucial SSD patterns
        'INTEL SSDSF\w+', 'INTEL 545S', 'INTEL 540S',  # Intel SSD patterns
        'KINGSTON SA\d+S\d+', 'KINGSTON SUV\d+',  # Kingston SSD patterns
        'SANDISK PLUS', 'SANDISK ULTRA', 'SANDISK EXTREME',  # SanDisk SSD patterns
        'TRANSCEND TS\d+GSSD', 'PNY CS\d+',  # Other SSD patterns
        'PATRIOT BURST', 'ADATA SU\d+', 'ADATA SP\d+'  # Additional SSD patterns
    )
    
    # HDD patterns
    $hddIndicators = @(
        'HDD', 'SATA', 'BARRACUDA', 'CAVIAR', 'DESKSTAR', 'SPINPOINT',
        'WD\d+\w+', 'ST\d+DM\d+', 'ST\d+LM\d+',  # Common HDD patterns
        'HITACHI HTS\d+', 'TOSHIBA MQ\d+', 'HGST',  # HDD manufacturer patterns
        'SEAGATE ST\d+', 'MAXTOR', 'QUANTUM',  # Additional HDD patterns
        'WESTERN DIGITAL', 'WD BLUE HDD', 'WD BLACK HDD'  # WD HDD patterns
    )
    
    # Check for NVMe indicators first (highest priority for modern drives)
    ForEach ($indicator in $nvmeIndicators) {
        If ($combinedString -match $indicator) {
            Write-Log -LogLevel 'INFO' -Message "Drive identified as NVMe based on pattern: $indicator"
            Return 'NVMe'
        }
    }
    
    # Check for SSD indicators
    ForEach ($indicator in $ssdIndicators) {
        If ($combinedString -match $indicator) {
            Write-Log -LogLevel 'INFO' -Message "Drive identified as SSD based on pattern: $indicator"
            Return 'SSD'
        }
    }
    
    # Check for HDD indicators
    ForEach ($indicator in $hddIndicators) {
        If ($combinedString -match $indicator) {
            Write-Log -LogLevel 'INFO' -Message "Drive identified as HDD based on pattern: $indicator"
            Return 'HDD'
        }
    }
    
    # Additional logic based on interface type
    If ($InterfaceType -eq 'SCSI' -and $Model -match 'SAMSUNG.*\w{2}\d{4}\w{8}-\w{5}') {
        Write-Log -LogLevel 'INFO' -Message "Drive identified as NVMe based on Samsung NVMe naming pattern and SCSI interface"
        Return 'NVMe'
    }
    
    Write-Log -LogLevel 'WARNING' -Message "Could not determine drive type for: $Model (Manufacturer: $Manufacturer, Interface: $InterfaceType)"
    Return 'Unknown'
}

Function Get-SmartStatus {
    <#
    .SYNOPSIS
        Retrieves SMART health status for all physical disks using multiple fallback methods.
        
    .DESCRIPTION
        This function attempts multiple methods to retrieve SMART status, starting with modern
        CIM methods and falling back to legacy WMI and WMIC commands as needed.
        
    .OUTPUTS
        Array of hashtables containing SMART status information
        
    .EXAMPLE
        $smartStatus = Get-SmartStatus
        
    .NOTES
        Uses multiple fallback methods to handle NVMe drives, VMs, and legacy systems.
    #>
    [CmdletBinding()]
    Param()
    
    Try {
        Write-Log -LogLevel 'INFO' -Message 'Retrieving SMART health status using multiple methods'
        
        $smartStatusList = [System.Collections.Generic.List[PSObject]]::new()
        
        # Method 1: Try Get-CimInstance (Modern approach)
        Try {
            Write-Log -LogLevel 'INFO' -Message 'Attempting SMART retrieval via Get-CimInstance'
            $smartData = Get-CimInstance -Namespace 'root\wmi' -ClassName 'MSStorageDriver_FailurePredictStatus' -ErrorAction Stop
            
            ForEach ($smart in $smartData) {
                $smartInfo = @{
                    'InstanceName' = $smart.InstanceName
                    'PredictFailure' = [Bool]$smart.PredictFailure
                    'Reason' = If ($smart.Reason) { $smart.Reason } Else { 0 }
                    'Active' = [Bool]$smart.Active
                    'Method' = 'CimInstance'
                }
                $smartStatusList.Add([PSCustomObject]$smartInfo)
            }
            
            Write-Log -LogLevel 'SUCCESS' -Message "Retrieved SMART status via CimInstance for $($smartStatusList.Count) drives"
            
        } Catch {
            Write-Log -LogLevel 'WARNING' -Message "CimInstance method failed: $($_.Exception.Message)."
        }
        
        # Method 4: Basic disk status check if SMART methods failed
        If ($smartStatusList.Count -eq 0) {
            Write-Log -LogLevel 'INFO' -Message 'All SMART methods failed. Attempting basic disk status check.'
            Try {
                $diskDrives = Get-CimInstance -ClassName 'Win32_DiskDrive' -ErrorAction Stop
                ForEach ($drive in $diskDrives) {
                    $predictFailure = $false
                    $reason = 0
                    
                    # Map status to failure prediction
                    Switch ($drive.Status) {
                        'Pred Fail' { $predictFailure = $true; $reason = 1 }
                        'Error' { $predictFailure = $true; $reason = 2 }
                        'Unknown' { $predictFailure = $false; $reason = 3 }
                        'Degraded' { $predictFailure = $true; $reason = 4 }
                        Default { $predictFailure = $false; $reason = 0 }
                    }
                    
                    $smartInfo = @{
                        'InstanceName' = $drive.PNPDeviceID
                        'PredictFailure' = $predictFailure
                        'Reason' = $reason
                        'Active' = $true
                        'Method' = 'Win32_DiskDrive'
                        'BasicStatus' = $drive.Status
                    }
                    $smartStatusList.Add([PSCustomObject]$smartInfo)
                }
                
                Write-Log -LogLevel 'SUCCESS' -Message "Retrieved basic disk status for $($smartStatusList.Count) drives"
                
            } Catch {
                Write-Log -LogLevel 'ERROR' -Message "All SMART retrieval methods failed: $($_.Exception.Message)"
            }
        }
        
        Return $smartStatusList.ToArray()
        
    } Catch {
        Write-Log -LogLevel 'ERROR' -Message "Critical error in SMART status retrieval: $($_.Exception.Message)"
        Return @()
    }
}

Function Get-StorageReliabilityCounters {
    <#
    .SYNOPSIS
        Retrieves detailed SMART attributes from storage reliability counters with multiple fallback methods.
        
    .DESCRIPTION
        This function uses multiple approaches to retrieve detailed SMART attributes including
        Get-StorageReliabilityCounter for modern systems and fallback methods for compatibility.
        
    .OUTPUTS
        Array of hashtables containing detailed SMART attributes
        
    .EXAMPLE
        $reliabilityCounters = Get-StorageReliabilityCounters
        
    .NOTES
        Uses multiple methods to ensure compatibility across different Windows versions and drive types.
    #>
    [CmdletBinding()]
    Param()
    
    Try {
        Write-Log -LogLevel 'INFO' -Message 'Retrieving detailed SMART attributes using multiple methods'
        
        $reliabilityList = [System.Collections.Generic.List[PSObject]]::new()
        
        # Method 1: Try Get-StorageReliabilityCounter (Preferred for Windows 8/2012+)
        Try {
            Write-Log -LogLevel 'INFO' -Message 'Attempting SMART retrieval via Get-StorageReliabilityCounter'
            
            # Try with Get-PhysicalDisk first
            $physicalDisks = Get-PhysicalDisk -ErrorAction Stop
            
            ForEach ($disk in $physicalDisks) {
                Try {
                    Write-Log -LogLevel 'INFO' -Message "Getting reliability counters for disk: $($disk.FriendlyName)"
                    
                    $reliabilityCounters = $disk | Get-StorageReliabilityCounter -ErrorAction Stop
                    
                    If ($reliabilityCounters) {
                        $reliabilityInfo = @{
                            'DeviceId' = $disk.DeviceId
                            'FriendlyName' = $disk.FriendlyName
                            'SerialNumber' = $disk.SerialNumber
                            'MediaType' = $disk.MediaType
                            'Temperature' = $reliabilityCounters.Temperature
                            'TemperatureMax' = $reliabilityCounters.TemperatureMax
                            'Wear' = $reliabilityCounters.Wear
                            'PowerOnHours' = $reliabilityCounters.PowerOnHours
                            'ReadErrorsTotal' = $reliabilityCounters.ReadErrorsTotal
                            'ReadErrorsCorrected' = $reliabilityCounters.ReadErrorsCorrected
                            'ReadErrorsUncorrected' = $reliabilityCounters.ReadErrorsUncorrected
                            'WriteErrorsTotal' = $reliabilityCounters.WriteErrorsTotal
                            'WriteErrorsCorrected' = $reliabilityCounters.WriteErrorsCorrected
                            'WriteErrorsUncorrected' = $reliabilityCounters.WriteErrorsUncorrected
                            'Method' = 'Get-StorageReliabilityCounter'
                        }
                        
                        $reliabilityList.Add([PSCustomObject]$reliabilityInfo)
                        Write-Log -LogLevel 'SUCCESS' -Message "Retrieved reliability counters for: $($disk.FriendlyName)"
                    }
                    
                } Catch {
                    Write-Log -LogLevel 'WARNING' -Message "Failed to get reliability counters for $($disk.FriendlyName): $($_.Exception.Message)"
                }
            }
            
            Write-Log -LogLevel 'SUCCESS' -Message "Retrieved detailed SMART attributes for $($reliabilityList.Count) drives via StorageReliabilityCounter"
            
        } Catch {
            Write-Log -LogLevel 'WARNING' -Message "StorageReliabilityCounter method failed: $($_.Exception.Message). Trying alternative methods."
            
            # Method 2: Try Get-Disk with Get-StorageReliabilityCounter
            Try {
                Write-Log -LogLevel 'INFO' -Message 'Attempting SMART retrieval via Get-Disk | Get-StorageReliabilityCounter'
                
                $disks = Get-Disk -ErrorAction Stop
                
                ForEach ($disk in $disks) {
                    Try {
                        $reliabilityCounters = $disk | Get-StorageReliabilityCounter -ErrorAction Stop
                        
                        If ($reliabilityCounters) {
                            $reliabilityInfo = @{
                                'DeviceId' = $disk.Number
                                'FriendlyName' = "Disk $($disk.Number)"
                                'SerialNumber' = $disk.SerialNumber
                                'MediaType' = 'Unknown'
                                'Temperature' = $reliabilityCounters.Temperature
                                'TemperatureMax' = $reliabilityCounters.TemperatureMax
                                'Wear' = $reliabilityCounters.Wear
                                'PowerOnHours' = $reliabilityCounters.PowerOnHours
                                'ReadErrorsTotal' = $reliabilityCounters.ReadErrorsTotal
                                'ReadErrorsCorrected' = $reliabilityCounters.ReadErrorsCorrected
                                'ReadErrorsUncorrected' = $reliabilityCounters.ReadErrorsUncorrected
                                'WriteErrorsTotal' = $reliabilityCounters.WriteErrorsTotal
                                'WriteErrorsCorrected' = $reliabilityCounters.WriteErrorsCorrected
                                'WriteErrorsUncorrected' = $reliabilityCounters.WriteErrorsUncorrected
                                'Method' = 'Get-Disk-StorageReliabilityCounter'
                            }
                            
                            $reliabilityList.Add([PSCustomObject]$reliabilityInfo)
                            Write-Log -LogLevel 'SUCCESS' -Message "Retrieved reliability counters for: Disk $($disk.Number)"
                        }
                        
                    } Catch {
                        Write-Log -LogLevel 'WARNING' -Message "Failed to get reliability counters for Disk $($disk.Number): $($_.Exception.Message)"
                    }
                }
                
                Write-Log -LogLevel 'SUCCESS' -Message "Retrieved detailed SMART attributes for $($reliabilityList.Count) drives via Get-Disk method"
                
            } Catch {
                Write-Log -LogLevel 'WARNING' -Message "Get-Disk method failed: $($_.Exception.Message)"
            }
        }
        
        # Method 3: Basic disk health check if modern methods fail
        If ($reliabilityList.Count -eq 0) {
            Write-Log -LogLevel 'INFO' -Message 'Modern SMART methods unavailable. Using basic health checks.'
            Try {
                $physicalDisks = Get-PhysicalDisk -ErrorAction Stop
                
                ForEach ($disk in $physicalDisks) {
                    $reliabilityInfo = @{
                        'DeviceId' = $disk.DeviceId
                        'FriendlyName' = $disk.FriendlyName
                        'SerialNumber' = $disk.SerialNumber
                        'MediaType' = $disk.MediaType
                        'Temperature' = $null
                        'TemperatureMax' = $null
                        'Wear' = $null
                        'PowerOnHours' = $null
                        'ReadErrorsTotal' = $null
                        'ReadErrorsCorrected' = $null
                        'ReadErrorsUncorrected' = $null
                        'WriteErrorsTotal' = $null
                        'WriteErrorsCorrected' = $null
                        'WriteErrorsUncorrected' = $null
                        'Method' = 'Get-PhysicalDisk-BasicOnly'
                        'HealthStatus' = $disk.HealthStatus
                        'OperationalStatus' = $disk.OperationalStatus
                    }
                    
                    $reliabilityList.Add([PSCustomObject]$reliabilityInfo)
                }
                
                Write-Log -LogLevel 'SUCCESS' -Message "Retrieved basic disk information for $($reliabilityList.Count) drives"
                
            } Catch {
                Write-Log -LogLevel 'ERROR' -Message "All reliability counter methods failed: $($_.Exception.Message)"
            }
        }
        
        Return $reliabilityList.ToArray()
        
    } Catch {
        Write-Log -LogLevel 'ERROR' -Message "Critical error in storage reliability counter retrieval: $($_.Exception.Message)"
        Return @()
    }
}

Function Invoke-SmartAnalysis {
    <#
    .SYNOPSIS
        Optimized SMART analysis that performs wear detection only once per drive.
        
    .DESCRIPTION
        This optimized function performs wear detection once per drive and passes the results
        to the analysis functions, eliminating redundant calls and improving performance.
        
    .PARAMETER DiskInfo
        Array of disk information objects
        
    .PARAMETER SmartStatus
        Array of SMART status objects
        
    .PARAMETER ReliabilityCounters
        Array of reliability counter objects
        
    .OUTPUTS
        Hashtable containing analysis results and failure predictions
        
    .EXAMPLE
        $analysis = Invoke-SmartAnalysisOptimized -DiskInfo $disks -SmartStatus $smart -ReliabilityCounters $reliability
        
    .NOTES
        Optimized version that eliminates redundant wear detection calls.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [Array]$DiskInfo,
        
        [Parameter(Mandatory = $true)]
        [Array]$SmartStatus,
        
        [Parameter(Mandatory = $false)]
        [Array]$ReliabilityCounters = @()
    )
    
    Try {
        Write-Log -LogLevel 'INFO' -Message 'Starting optimized SMART analysis with single wear detection per drive'
        
        $analysisResults = @{
            'OverallStatus' = 'Healthy'
            'CriticalIssues' = [System.Collections.Generic.List[PSObject]]::new()
            'WarningIssues' = [System.Collections.Generic.List[PSObject]]::new()
            'HealthyDrives' = [System.Collections.Generic.List[PSObject]]::new()
            'TotalDrives' = $DiskInfo.Count
            'FailingDrives' = 0
            'AnalysisTimestamp' = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        }
        
        ForEach ($disk in $DiskInfo) {
            Try {
                Write-Log -LogLevel 'INFO' -Message "Analyzing SMART data for disk: $($disk.Model) (Type: $($disk.DriveType))"
                
                $driveAnalysis = @{
                    'DiskInfo' = $disk
                    'HealthStatus' = 'Healthy'
                    'IssuesSeverity' = 'None'
                    'Issues' = [System.Collections.Generic.List[String]]::new()
                    'EstimatedTimeRemaining' = $null
                    'RecommendedAction' = 'Continue monitoring'
                    'SmartFailurePredicted' = $false
                    'FailureReason' = $null
                    'WearInformation' = $null
                }
                
                # Check basic SMART status
                $smartEntry = $SmartStatus | Where-Object { $_.InstanceName -like "*$($disk.DeviceID.Replace('\',''))*" }
                If ($smartEntry) {
                    $driveAnalysis['SmartFailurePredicted'] = $smartEntry.PredictFailure
                    $driveAnalysis['FailureReason'] = $smartEntry.Reason
                    
                    If ($smartEntry.PredictFailure) {
                        $driveAnalysis['HealthStatus'] = 'Critical'
                        $driveAnalysis['IssuesSeverity'] = 'Critical'
                        $driveAnalysis['Issues'].Add('🚨 SMART failure predicted by drive firmware')
                        $driveAnalysis['RecommendedAction'] = 'Replace drive immediately - backup data now'
                        $driveAnalysis['EstimatedTimeRemaining'] = 'Days to weeks'
                    }
                }
                
                # Check reliability counters if available
                $reliabilityEntry = $ReliabilityCounters | Where-Object { 
                    $_.SerialNumber -eq $disk.SerialNumber -or $_.FriendlyName -like "*$($disk.Model)*" 
                }
                
                If ($reliabilityEntry) {
                    Write-Log -LogLevel 'INFO' -Message "Found reliability data for $($disk.Model) - Method: $($reliabilityEntry.Method) - Drive Type: $($disk.DriveType)"
                    
                    # **OPTIMIZED**: Perform wear detection only ONCE per drive
                    $wearInfo = Get-WearInformation -DiskInfo $disk -ReliabilityData $reliabilityEntry
                    $driveAnalysis['WearInformation'] = $wearInfo
                    
                    # Log wear information once
                    If ($wearInfo['IsWearDataAvailable']) {
                        Write-Log -LogLevel 'INFO' -Message "Wear information for $($disk.Model): $($wearInfo['WearInterpretation']) (Method: $($wearInfo['WearMethod']), Status: $($wearInfo['WearStatus']))"
                    } Else {
                        Write-Log -LogLevel 'WARNING' -Message "Wear information not available for $($disk.Model) using method: $($wearInfo['WearMethod'])"
                    }
                    
                    # **OPTIMIZED**: Pass the wear information to analysis functions to avoid redundant calls
                    $criticalIssues = Test-CriticalSmartAttributes -ReliabilityData $reliabilityEntry -DriveType $disk.DriveType -WearInfo $wearInfo
                    $criticalIssuesCount = If ($criticalIssues -is [Array]) { $criticalIssues.Count } ElseIf ($criticalIssues) { 1 } Else { 0 }
                    
                    If ($criticalIssuesCount -gt 0) {
                        $driveAnalysis['HealthStatus'] = 'Critical'
                        $driveAnalysis['IssuesSeverity'] = 'Critical'
                        ForEach ($issue in $criticalIssues) {
                            $driveAnalysis['Issues'].Add($issue)
                        }
                        $driveAnalysis['RecommendedAction'] = 'Replace drive immediately - backup data now'
                        $driveAnalysis['EstimatedTimeRemaining'] = Get-EstimatedTimeRemaining -ReliabilityData $reliabilityEntry -IssueType 'Critical'
                    }
                    
                    # Check for warning conditions if not already critical
                    If ($driveAnalysis['HealthStatus'] -eq 'Healthy') {
                        # **OPTIMIZED**: Pass the same wear information to warning analysis
                        $warningIssues = Test-WarningSmartAttributes -ReliabilityData $reliabilityEntry -DriveType $disk.DriveType -WearInfo $wearInfo
                        $warningIssuesCount = If ($warningIssues -is [Array]) { $warningIssues.Count } ElseIf ($warningIssues) { 1 } Else { 0 }
                        
                        If ($warningIssuesCount -gt 0) {
                            $driveAnalysis['HealthStatus'] = 'Warning'
                            $driveAnalysis['IssuesSeverity'] = 'Warning'
                            ForEach ($issue in $warningIssues) {
                                $driveAnalysis['Issues'].Add($issue)
                            }
                            $driveAnalysis['RecommendedAction'] = 'Monitor closely - plan for replacement'
                            $driveAnalysis['EstimatedTimeRemaining'] = Get-EstimatedTimeRemaining -ReliabilityData $reliabilityEntry -IssueType 'Warning'
                        }
                    }
                    
                } Else {
                    Write-Log -LogLevel 'INFO' -Message "No reliability data found for $($disk.Model) - using basic health status only"
                    
                    # **OPTIMIZED**: Only get wear info once even without reliability data
                    $wearInfo = Get-EnhancedWearInformation -DiskInfo $disk -ReliabilityData $null
                    $driveAnalysis['WearInformation'] = $wearInfo
                    
                    If ($wearInfo['IsWearDataAvailable']) {
                        Write-Log -LogLevel 'INFO' -Message "Basic wear information for $($disk.Model): $($wearInfo['WearInterpretation']) (Method: $($wearInfo['WearMethod']), Status: $($wearInfo['WearStatus']))"
                    }
                }
                
                # Categorize drive based on analysis
                Switch ($driveAnalysis['HealthStatus']) {
                    'Critical' {
                        $analysisResults['CriticalIssues'].Add([PSCustomObject]$driveAnalysis)
                        $analysisResults['FailingDrives']++
                        $analysisResults['OverallStatus'] = 'Critical'
                    }
                    'Warning' {
                        $analysisResults['WarningIssues'].Add([PSCustomObject]$driveAnalysis)
                        If ($analysisResults['OverallStatus'] -eq 'Healthy') {
                            $analysisResults['OverallStatus'] = 'Warning'
                        }
                    }
                    Default {
                        $analysisResults['HealthyDrives'].Add([PSCustomObject]$driveAnalysis)
                    }
                }
                
                Write-Log -LogLevel 'SUCCESS' -Message "Completed optimized analysis for $($disk.Model) (Type: $($disk.DriveType)) - Status: $($driveAnalysis['HealthStatus'])"
                
            } Catch {
                Write-Log -LogLevel 'ERROR' -Message "Failed to analyze disk $($disk.Model): $($_.Exception.Message)"
            }
        }
        
        Write-Log -LogLevel 'SUCCESS' -Message "Optimized SMART analysis completed - Overall Status: $($analysisResults['OverallStatus']), Critical: $($analysisResults['CriticalIssues'].Count), Warning: $($analysisResults['WarningIssues'].Count)"
        Return $analysisResults
        
    } Catch {
        Write-Log -LogLevel 'ERROR' -Message "Optimized SMART analysis failed: $($_.Exception.Message)"
        Throw
    }
}

Function Get-WearInformation {
    <#
    .SYNOPSIS
        Gets comprehensive wear information for drives using multiple detection methods.
        
    .DESCRIPTION
        This function addresses the limitation where PowerShell's Get-StorageReliabilityCounter
        may report 0 wear for healthy drives. It uses multiple methods to get accurate wear data.
        
    .PARAMETER DiskInfo
        Disk information object containing drive details
        
    .PARAMETER ReliabilityData
        Storage reliability counter data
        
    .OUTPUTS
        Hashtable containing comprehensive wear information
        
    .EXAMPLE
        $wearInfo = Get-WearInformation -DiskInfo $disk -ReliabilityData $reliability
        
    .NOTES
        Handles different vendor implementations and PowerShell limitations with wear reporting.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [PSObject]$DiskInfo,
        
        [Parameter(Mandatory = $false)]
        [PSObject]$ReliabilityData
    )
    
    Try {
        Write-Log -LogLevel 'INFO' -Message "Getting wear information for $($DiskInfo.Model)"
        
        $wearInfo = @{
            'WearMethod' = 'Unknown'
            'WearPercentageUsed' = $null
            'WearPercentageRemaining' = $null
            'IsWearDataAvailable' = $false
            'WearInterpretation' = 'Unknown'
            'WearStatus' = 'Unknown'
        }
        
        # Method 1: Try PowerShell Get-StorageReliabilityCounter
        If ($ReliabilityData -and $null -ne $ReliabilityData.Wear) {
            $wearValue = $ReliabilityData.Wear
            $wearInfo['WearMethod'] = 'PowerShell-StorageReliabilityCounter'
            $wearInfo['IsWearDataAvailable'] = $true
            
            # PowerShell wear interpretation varies by vendor
            If ($wearValue -eq 0) {
                # Could mean: no wear (healthy) OR data not available
                $wearInfo['WearPercentageUsed'] = 0
                $wearInfo['WearPercentageRemaining'] = 100
                $wearInfo['WearInterpretation'] = 'Minimal wear detected (or data not available)'
                $wearInfo['WearStatus'] = 'Healthy'
                Write-Log -LogLevel 'INFO' -Message "PowerShell wear shows 0 - interpreting as healthy drive"
            } ElseIf ($wearValue -gt 0 -and $wearValue -le 100) {
                # Determine if this represents used or remaining based on drive type and value
                If ($DiskInfo.DriveType -eq 'NVMe') {
                    # NVMe typically reports percentage used
                    $wearInfo['WearPercentageUsed'] = $wearValue
                    $wearInfo['WearPercentageRemaining'] = 100 - $wearValue
                    $wearInfo['WearInterpretation'] = "NVMe percentage used: $wearValue%"
                } Else {
                    # For SSD/HDD, could be either - use context clues
                    If ($wearValue -gt 90) {
                        # Likely represents remaining life (new drive)
                        $wearInfo['WearPercentageRemaining'] = $wearValue
                        $wearInfo['WearPercentageUsed'] = 100 - $wearValue
                        $wearInfo['WearInterpretation'] = "Life remaining: $wearValue%"
                    } Else {
                        # Likely represents wear used
                        $wearInfo['WearPercentageUsed'] = $wearValue
                        $wearInfo['WearPercentageRemaining'] = 100 - $wearValue
                        $wearInfo['WearInterpretation'] = "Wear used: $wearValue%"
                    }
                }
                
                # Determine status
                If ($wearInfo['WearPercentageRemaining'] -le 10) {
                    $wearInfo['WearStatus'] = 'Critical'
                } ElseIf ($wearInfo['WearPercentageRemaining'] -le 25) {
                    $wearInfo['WearStatus'] = 'Warning'
                } Else {
                    $wearInfo['WearStatus'] = 'Healthy'
                }
            }
        }
        
        # Method 2: Try to get NVMe-specific wear via WMI (if available)
        If (-not $wearInfo['IsWearDataAvailable'] -and $DiskInfo.DriveType -eq 'NVMe') {
            Try {
                Write-Log -LogLevel 'INFO' -Message 'Attempting NVMe-specific wear detection via WMI'
                $nvmeWear = Get-NVMeWearViaWMI -DeviceID $DiskInfo.DeviceID
                If ($nvmeWear -ne $null) {
                    $wearInfo['WearMethod'] = 'NVMe-WMI'
                    $wearInfo['WearPercentageUsed'] = $nvmeWear
                    $wearInfo['WearPercentageRemaining'] = 100 - $nvmeWear
                    $wearInfo['IsWearDataAvailable'] = $true
                    $wearInfo['WearInterpretation'] = "NVMe WMI percentage used: $nvmeWear%"
                    
                    If ($nvmeWear -ge 90) {
                        $wearInfo['WearStatus'] = 'Critical'
                    } ElseIf ($nvmeWear -ge 75) {
                        $wearInfo['WearStatus'] = 'Warning'
                    } Else {
                        $wearInfo['WearStatus'] = 'Healthy'
                    }
                }
            } Catch {
                Write-Log -LogLevel 'WARNING' -Message "NVMe WMI wear detection failed: $($_.Exception.Message)"
            }
        }
        
        # Method 3: Alternative PowerShell approach with specific selection
        If (-not $wearInfo['IsWearDataAvailable']) {
            Try {
                Write-Log -LogLevel 'INFO' -Message 'Attempting alternative PowerShell wear detection with specific selection'
                
                # Get disk by device ID and explicitly select wear
                $diskNumber = $DiskInfo.DiskIndex
                $specificWear = Get-PhysicalDisk | Where-Object { $_.DeviceId -eq $diskNumber } | Get-StorageReliabilityCounter | Select-Object -ExpandProperty Wear
                
                If ($null -ne $specificWear -and $specificWear -ne 0) {
                    $wearInfo['WearMethod'] = 'PowerShell-Specific-Selection'
                    $wearInfo['WearPercentageUsed'] = $specificWear
                    $wearInfo['WearPercentageRemaining'] = 100 - $specificWear
                    $wearInfo['IsWearDataAvailable'] = $true
                    $wearInfo['WearInterpretation'] = "Specific selection wear: $specificWear%"
                    
                    If ($specificWear -ge 90) {
                        $wearInfo['WearStatus'] = 'Critical'
                    } ElseIf ($specificWear -ge 75) {
                        $wearInfo['WearStatus'] = 'Warning'
                    } Else {
                        $wearInfo['WearStatus'] = 'Healthy'
                    }
                }
            } Catch {
                Write-Log -LogLevel 'WARNING' -Message "Alternative PowerShell wear detection failed: $($_.Exception.Message)"
            }
        }
        
        # Method 4: Estimate based on power-on hours and drive type
        If (-not $wearInfo['IsWearDataAvailable'] -and $ReliabilityData -and $null -ne $ReliabilityData.PowerOnHours) {
            $estimatedWear = Get-EstimatedWearFromPowerOnHours -PowerOnHours $ReliabilityData.PowerOnHours -DriveType $DiskInfo.DriveType
            If ($estimatedWear -ne $null) {
                $wearInfo['WearMethod'] = 'Estimated-PowerOnHours'
                $wearInfo['WearPercentageUsed'] = $estimatedWear
                $wearInfo['WearPercentageRemaining'] = 100 - $estimatedWear
                $wearInfo['IsWearDataAvailable'] = $true
                $wearInfo['WearInterpretation'] = "Estimated from power-on hours: $estimatedWear%"
                
                If ($estimatedWear -ge 90) {
                    $wearInfo['WearStatus'] = 'Critical'
                } ElseIf ($estimatedWear -ge 75) {
                    $wearInfo['WearStatus'] = 'Warning'
                } Else {
                    $wearInfo['WearStatus'] = 'Healthy'
                }
            }
        }
        
        # Log the results
        Write-Log -LogLevel 'INFO' -Message "Wear detection for $($DiskInfo.Model): Method=$($wearInfo['WearMethod']), Available=$($wearInfo['IsWearDataAvailable']), Status=$($wearInfo['WearStatus'])"
        If ($wearInfo['IsWearDataAvailable']) {
            Write-Log -LogLevel 'INFO' -Message "Wear details: Used=$($wearInfo['WearPercentageUsed'])%, Remaining=$($wearInfo['WearPercentageRemaining'])%, Interpretation=$($wearInfo['WearInterpretation'])"
        }
        
        Return $wearInfo
        
    } Catch {
        Write-Log -LogLevel 'ERROR' -Message "Failed to get wear information: $($_.Exception.Message)"
        Return @{
            'WearMethod' = 'Error'
            'WearPercentageUsed' = $null
            'WearPercentageRemaining' = $null
            'IsWearDataAvailable' = $false
            'WearInterpretation' = 'Error retrieving wear data'
            'WearStatus' = 'Unknown'
        }
    }
}

Function Get-NVMeWearViaWMI {
    <#
    .SYNOPSIS
        Attempts to get NVMe wear data via WMI queries.
        
    .DESCRIPTION
        This function tries alternative WMI approaches to get NVMe wear data
        when PowerShell's Get-StorageReliabilityCounter doesn't provide accurate data.
        
    .PARAMETER DeviceID
        Device ID of the NVMe drive
        
    .OUTPUTS
        Integer representing wear percentage or null if not available
        
    .NOTES
        This is an experimental approach for drives where standard methods fail.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [String]$DeviceID
    )
    
    Try {
        # Try to get NVMe-specific SMART data via WMI
        # This may not work on all systems but worth trying
        
        # Method 1: Try Win32_PerfRawData_Counters_StorageAdapter
        Try {
            $storageAdapter = Get-CimInstance -ClassName 'Win32_PerfRawData_Counters_StorageAdapter' -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*$DeviceID*" }
            If ($storageAdapter) {
                # Look for wear-related properties
                # This is highly vendor-specific
                Write-Log -LogLevel 'INFO' -Message 'Found storage adapter data, but no standard wear property available'
            }
        } Catch {
            Write-Log -LogLevel 'WARNING' -Message "Storage adapter query failed: $($_.Exception.Message)"
        }
        
        # Method 2: Try MSStorageDriver_FailurePredictData for raw SMART attributes
        Try {
            $smartData = Get-CimInstance -Namespace 'root\wmi' -ClassName 'MSStorageDriver_FailurePredictData' -ErrorAction SilentlyContinue | Where-Object { $_.InstanceName -like "*$DeviceID*" }
            If ($smartData -and $smartData.VendorSpecific) {
                # Parse vendor-specific SMART data for wear indicators
                # This requires knowing the specific vendor's SMART attribute layout
                Write-Log -LogLevel 'INFO' -Message 'Found SMART data, but vendor-specific parsing not implemented'
            }
        } Catch {
            Write-Log -LogLevel 'WARNING' -Message "SMART data query failed: $($_.Exception.Message)"
        }
        
        # For now, return null as we don't have a universal WMI method
        Return $null
        
    } Catch {
        Write-Log -LogLevel 'ERROR' -Message "NVMe WMI wear detection failed: $($_.Exception.Message)"
        Return $null
    }
}

Function Get-EstimatedWearFromPowerOnHours {
    <#
    .SYNOPSIS
        Estimates wear percentage based on power-on hours and drive type.
        
    .DESCRIPTION
        When direct wear data is not available, this function provides a rough estimate
        based on power-on hours and typical drive lifespans.
        
    .PARAMETER PowerOnHours
        Number of power-on hours
        
    .PARAMETER DriveType
        Type of drive (NVMe, SSD, HDD)
        
    .OUTPUTS
        Integer representing estimated wear percentage or null if cannot estimate
        
    .NOTES
        This is a rough estimate only and should not be relied upon for critical decisions.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [Int]$PowerOnHours,
        
        [Parameter(Mandatory = $true)]
        [String]$DriveType
    )
    
    Try {
        # Define typical lifespans for different drive types (in hours)
        $typicalLifespan = Switch ($DriveType) {
            'NVMe' { 43800 }    # 5 years (NVMe drives typically have good endurance)
            'SSD' { 35040 }     # 4 years (SATA SSDs)
            'HDD' { 52560 }     # 6 years (HDDs often last longer in hours but fail mechanically)
            Default { 43800 }   # Default to 5 years
        }
        
        # Calculate percentage
        $estimatedWear = [Math]::Round(($PowerOnHours / $typicalLifespan) * 100, 0)
        
        # Cap at 100%
        If ($estimatedWear -gt 100) {
            $estimatedWear = 100
        }
        
        Write-Log -LogLevel 'INFO' -Message "Estimated wear for $DriveType drive: $estimatedWear% (based on $PowerOnHours hours vs $typicalLifespan typical lifespan)"
        
        Return $estimatedWear
        
    } Catch {
        Write-Log -LogLevel 'ERROR' -Message "Failed to estimate wear from power-on hours: $($_.Exception.Message)"
        Return $null
    }
}

Function Test-CriticalSmartAttributes {
    <#
    .SYNOPSIS
        Optimized critical SMART attribute testing that uses pre-calculated wear information.
        
    .DESCRIPTION
        This optimized function receives wear information as a parameter instead of
        calculating it again, eliminating redundant wear detection calls.
        
    .PARAMETER ReliabilityData
        Storage reliability counter data for the drive
        
    .PARAMETER DriveType
        Type of drive (NVMe, SSD, HDD, Unknown)
        
    .PARAMETER WearInfo
        Pre-calculated wear information to avoid redundant detection
        
    .OUTPUTS
        Array of critical issue descriptions
        
    .NOTES
        Optimized version that uses pre-calculated wear information.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [PSObject]$ReliabilityData,
        
        [Parameter(Mandatory = $true)]
        [String]$DriveType,
        
        [Parameter(Mandatory = $true)]
        [Hashtable]$WearInfo
    )
    
    $criticalIssues = [System.Collections.Generic.List[String]]::new()
    
    Try {
        Write-Log -LogLevel 'INFO' -Message "Testing critical SMART attributes for $DriveType drive (optimized - using pre-calculated wear data)"
        
        # Check if we have any reliability data to analyze
        If (-not $ReliabilityData) {
            Write-Log -LogLevel 'WARNING' -Message 'No reliability data provided for critical analysis'
            Return @()
        }
        
        # **OPTIMIZED**: Use pre-calculated wear information instead of detecting again
        If ($WearInfo['IsWearDataAvailable']) {
            If ($WearInfo['WearStatus'] -eq 'Critical') {
                $criticalIssues.Add("💾 $DriveType critical wear: $($WearInfo['WearInterpretation']) - Replace immediately")
            }
        }
        
        # Continue with other critical checks (same as before)
        # Critical: Any uncorrected read/write errors
        If ($null -ne $ReliabilityData.ReadErrorsUncorrected -and $ReliabilityData.ReadErrorsUncorrected -gt 0) {
            $criticalIssues.Add("🚨 Uncorrected read errors detected: $($ReliabilityData.ReadErrorsUncorrected) (CRITICAL - Drive failure imminent)")
        }
        
        If ($null -ne $ReliabilityData.WriteErrorsUncorrected -and $ReliabilityData.WriteErrorsUncorrected -gt 0) {
            $criticalIssues.Add("🚨 Uncorrected write errors detected: $($ReliabilityData.WriteErrorsUncorrected) (CRITICAL - Drive failure imminent)")
        }
        
        # Critical: Excessive temperature
        If ($null -ne $ReliabilityData.Temperature -and $ReliabilityData.Temperature -gt $script:CriticalThresholds['Temperature'].Critical) {
            $criticalIssues.Add("🌡️ Drive temperature critical: $($ReliabilityData.Temperature)°C (Threshold: $($script:CriticalThresholds['Temperature'].Critical)°C)")
        }
        
        # Critical: Excessive power-on hours
        If ($null -ne $ReliabilityData.PowerOnHours -and $ReliabilityData.PowerOnHours -gt $script:CriticalThresholds['PowerOnHours'].Critical) {
            $yearsOfOperation = [Math]::Round($ReliabilityData.PowerOnHours / 8760, 1)
            $criticalIssues.Add("⏰ Drive age critical: $($ReliabilityData.PowerOnHours) hours ($yearsOfOperation years) - High statistical failure rate")
        }
        
        # Check for basic health status if available
        If ($ReliabilityData.PSObject.Properties['HealthStatus'] -and $ReliabilityData.HealthStatus -eq 'Unhealthy') {
            $criticalIssues.Add("🚨 Drive health status reports: Unhealthy")
        }
        
        If ($ReliabilityData.PSObject.Properties['OperationalStatus'] -and $ReliabilityData.OperationalStatus -eq 'Degraded') {
            $criticalIssues.Add("⚠️ Drive operational status: Degraded")
        }
        
        Write-Log -LogLevel 'INFO' -Message "Optimized critical analysis found $($criticalIssues.Count) issues for $DriveType drive"
        Return $criticalIssues.ToArray()
        
    } Catch {
        Write-Log -LogLevel 'ERROR' -Message "Failed to test critical SMART attributes: $($_.Exception.Message)"
        Return @()
    }
}

Function Test-WarningSmartAttributes {
    <#
    .SYNOPSIS
        Optimized warning SMART attribute testing that uses pre-calculated wear information.
        
    .DESCRIPTION
        This optimized function receives wear information as a parameter instead of
        calculating it again, eliminating redundant wear detection calls.
        
    .PARAMETER ReliabilityData
        Storage reliability counter data for the drive
        
    .PARAMETER DriveType
        Type of drive (NVMe, SSD, HDD, Unknown)
        
    .PARAMETER WearInfo
        Pre-calculated wear information to avoid redundant detection
        
    .OUTPUTS
        Array of warning issue descriptions
        
    .NOTES
        Optimized version that uses pre-calculated wear information.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [PSObject]$ReliabilityData,
        
        [Parameter(Mandatory = $true)]
        [String]$DriveType,
        
        [Parameter(Mandatory = $true)]
        [Hashtable]$WearInfo
    )
    
    $warningIssues = [System.Collections.Generic.List[String]]::new()
    
    Try {
        Write-Log -LogLevel 'INFO' -Message "Testing warning SMART attributes for $DriveType drive (optimized - using pre-calculated wear data)"
        
        # Check if we have any reliability data to analyze
        If (-not $ReliabilityData) {
            Write-Log -LogLevel 'WARNING' -Message 'No reliability data provided for warning analysis'
            Return @()
        }
        
        # **OPTIMIZED**: Use pre-calculated wear information instead of detecting again
        If ($WearInfo['IsWearDataAvailable']) {
            If ($WearInfo['WearStatus'] -eq 'Warning') {
                $warningIssues.Add("💾 $DriveType wear warning: $($WearInfo['WearInterpretation']) - Plan for replacement")
            }
        }
        
        # Continue with other warning checks (same as before)
        # Warning: Corrected errors
        If ($null -ne $ReliabilityData.ReadErrorsCorrected -and $ReliabilityData.ReadErrorsCorrected -gt 100) {
            $warningIssues.Add("⚠️ High corrected read errors: $($ReliabilityData.ReadErrorsCorrected) (Drive working harder to read data)")
        }
        
        If ($null -ne $ReliabilityData.WriteErrorsCorrected -and $ReliabilityData.WriteErrorsCorrected -gt 100) {
            $warningIssues.Add("⚠️ High corrected write errors: $($ReliabilityData.WriteErrorsCorrected) (Drive working harder to write data)")
        }
        
        # Warning: Elevated temperature
        If ($null -ne $ReliabilityData.Temperature -and $ReliabilityData.Temperature -gt $script:CriticalThresholds['Temperature'].Warning) {
            $warningIssues.Add("🌡️ Drive temperature elevated: $($ReliabilityData.Temperature)°C (Warning threshold: $($script:CriticalThresholds['Temperature'].Warning)°C)")
        }
        
        # Warning: High power-on hours
        If ($null -ne $ReliabilityData.PowerOnHours -and $ReliabilityData.PowerOnHours -gt $script:CriticalThresholds['PowerOnHours'].Warning) {
            $yearsOfOperation = [Math]::Round($ReliabilityData.PowerOnHours / 8760, 1)
            $warningIssues.Add("⏰ Drive age warning: $($ReliabilityData.PowerOnHours) hours ($yearsOfOperation years) - Monitor for increased failure rate")
        }
        
        Write-Log -LogLevel 'INFO' -Message "Optimized warning analysis found $($warningIssues.Count) issues for $DriveType drive"
        Return $warningIssues.ToArray()
        
    } Catch {
        Write-Log -LogLevel 'ERROR' -Message "Failed to test warning SMART attributes: $($_.Exception.Message)"
        Return @()
    }
}

Function Get-EstimatedTimeRemaining {
    <#
    .SYNOPSIS
        Estimates time remaining before drive failure based on SMART attributes.
        
    .DESCRIPTION
        This function provides estimates of remaining drive life based on current SMART attributes
        and known failure patterns from industry research. Estimates are conservative and should be
        used for planning purposes only.
        
    .PARAMETER ReliabilityData
        Storage reliability counter data for the drive
        
    .PARAMETER IssueType
        Type of issue detected (Critical, Warning)
        
    .OUTPUTS
        String containing estimated time remaining or null if cannot be determined
        
    .EXAMPLE
        $timeRemaining = Get-EstimatedTimeRemaining -ReliabilityData $data -IssueType 'Critical'
        
    .NOTES
        Estimates based on Backblaze and Google studies. Actual failure times can vary significantly.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [PSObject]$ReliabilityData,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('Critical', 'Warning')]
        [String]$IssueType
    )
    
    Try {
        # Critical conditions typically indicate imminent failure
        If ($IssueType -eq 'Critical') {
            # Uncorrected errors indicate immediate danger
            If (($null -ne $ReliabilityData.ReadErrorsUncorrected -and $ReliabilityData.ReadErrorsUncorrected -gt 0) -or
                ($null -ne $ReliabilityData.WriteErrorsUncorrected -and $ReliabilityData.WriteErrorsUncorrected -gt 0)) {
                Return 'Hours to days (Replace immediately)'
            }
            
            # Critical temperature can cause rapid failure
            If ($null -ne $ReliabilityData.Temperature -and $ReliabilityData.Temperature -gt $script:CriticalThresholds['Temperature'].Critical) {
                Return 'Days to weeks (Temperature damage)'
            }
            
            # Very high power-on hours
            If ($null -ne $ReliabilityData.PowerOnHours -and $ReliabilityData.PowerOnHours -gt $script:CriticalThresholds['PowerOnHours'].Critical) {
                Return 'Weeks to months (Age-related failure)'
            }
            
            # SSD/NVMe wear critical
            If ($null -ne $ReliabilityData.Wear -and $ReliabilityData.Wear -le 10) {
                Return 'Days to weeks (SSD/NVMe end of life)'
            }
        }
        
        # Warning conditions indicate reduced reliability
        If ($IssueType -eq 'Warning') {
            # High corrected errors indicate drive stress
            If (($null -ne $ReliabilityData.ReadErrorsCorrected -and $ReliabilityData.ReadErrorsCorrected -gt 500) -or
                ($null -ne $ReliabilityData.WriteErrorsCorrected -and $ReliabilityData.WriteErrorsCorrected -gt 500)) {
                Return 'Months (Monitor for degradation)'
            }
            
            # Elevated temperature
            If ($null -ne $ReliabilityData.Temperature -and $ReliabilityData.Temperature -gt $script:CriticalThresholds['Temperature'].Warning) {
                Return '6-12 months (Heat stress)'
            }
            
            # High but not critical power-on hours
            If ($null -ne $ReliabilityData.PowerOnHours -and $ReliabilityData.PowerOnHours -gt $script:CriticalThresholds['PowerOnHours'].Warning) {
                Return '1-2 years (Increased failure rate)'
            }
            
            # SSD/NVMe wear warning
            If ($null -ne $ReliabilityData.Wear -and $ReliabilityData.Wear -le 25 -and $ReliabilityData.Wear -gt 10) {
                Return '6-18 months (SSD/NVMe wearing out)'
            }
        }
        
        Return $null
        
    } Catch {
        Write-Log -LogLevel 'ERROR' -Message "Failed to estimate time remaining: $($_.Exception.Message)"
        Return $null
    }
}

#########################################################################################################################
#                                              Teams Notification Functions                                             #
#########################################################################################################################

Function Send-TeamsNotification {
    <#
    .SYNOPSIS
        Teams notification that includes detailed wear information.
        
    .DESCRIPTION
        This version includes wear detection information in the Teams notifications
        to provide better insight into drive health status.
        
    .PARAMETER SystemInfo
        System information hashtable containing device details
        
    .PARAMETER AnalysisResults
        SMART analysis results containing drive health information
        
    .PARAMETER WebhookUrl
        Teams webhook URL for sending the notification
        
    .OUTPUTS
        Boolean indicating success or failure of notification delivery
        
    .NOTES
        to include wear detection method and status information.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [Hashtable]$SystemInfo,
        
        [Parameter(Mandatory = $true)]
        [Hashtable]$AnalysisResults,
        
        [Parameter(Mandatory = $true)]
        [String]$WebhookUrl
    )
    
    Try {
        Write-Log -LogLevel 'INFO' -Message 'Creating Teams adaptive card notification with wear information'
        
        # Determine notification severity and styling
        $severity = $AnalysisResults['OverallStatus']
        $severityColor = Switch ($severity) {
            'Critical' { 'attention' }
            'Warning' { 'warning' }
            Default { 'good' }
        }
        
        $severityEmoji = Switch ($severity) {
            'Critical' { '🚨' }
            'Warning' { '⚠️' }
            Default { '✅' }
        }
        
        # Create main title and summary
        $mainTitle = "$severityEmoji SMART Disk Health Alert - $($SystemInfo['ComputerName'])"
        $summaryText = If ($severity -eq 'Critical') {
            "**CRITICAL**: $($AnalysisResults['FailingDrives']) of $($AnalysisResults['TotalDrives']) drives showing signs of imminent failure"
        } ElseIf ($severity -eq 'Warning') {
            "**WARNING**: Issues detected on $($AnalysisResults['WarningIssues'].Count) of $($AnalysisResults['TotalDrives']) drives"
        } Else {
            "All $($AnalysisResults['TotalDrives']) drives are healthy"
        }
        
        # Build card body (same structure as before, but with drive details)
        $cardBody = [System.Collections.Generic.List[PSObject]]::new()
        
        # Header section with device info
        $cardBody.Add(@{
            'type' = 'Container'
            'style' = $severityColor
            'items' = @(
                @{
                    'type' = 'TextBlock'
                    'text' = $mainTitle
                    'weight' = 'Bolder'
                    'size' = 'Large'
                    'wrap' = $true
                },
                @{
                    'type' = 'TextBlock'
                    'text' = $summaryText
                    'weight' = 'Bolder'
                    'wrap' = $true
                    'spacing' = 'Small'
                }
            )
            'padding' = 'Default'
        })
        
        # System information section (same as before)
        $systemFactSet = [System.Collections.Generic.List[PSObject]]::new()
        $systemFactSet.Add(@{ 'title' = '🖥️ **Device**'; 'value' = $SystemInfo['ComputerName'] })
        $systemFactSet.Add(@{ 'title' = '🏢 **Domain**'; 'value' = $SystemInfo['Domain'] })
        $systemFactSet.Add(@{ 'title' = '🏭 **Manufacturer**'; 'value' = $SystemInfo['Manufacturer'] })
        $systemFactSet.Add(@{ 'title' = '📱 **Model**'; 'value' = $SystemInfo['Model'] })
        $systemFactSet.Add(@{ 'title' = '💻 **OS**'; 'value' = "$($SystemInfo['OSName']) ($($SystemInfo['OSArchitecture']))" })
        $systemFactSet.Add(@{ 'title' = '🔄 **Last Boot**'; 'value' = $SystemInfo['LastBootTime'] })
        $systemFactSet.Add(@{ 'title' = '📊 **Analysis Time**'; 'value' = $AnalysisResults['AnalysisTimestamp'] })
        
        $cardBody.Add(@{
            'type' = 'Container'
            'items' = @(
                @{
                    'type' = 'TextBlock'
                    'text' = '📋 **Device Information**'
                    'weight' = 'Bolder'
                    'size' = 'Medium'
                    'spacing' = 'Medium'
                },
                @{
                    'type' = 'FactSet'
                    'facts' = $systemFactSet.ToArray()
                    'spacing' = 'Small'
                }
            )
        })
        
        # **ENHANCED**: Critical issues section with wear information
        If ($AnalysisResults['CriticalIssues'].Count -gt 0) {
            $criticalContainer = @{
                'type' = 'Container'
                'style' = 'attention'
                'items' = [System.Collections.Generic.List[PSObject]]@(
                    @{
                        'type' = 'TextBlock'
                        'text' = "🚨 **CRITICAL ISSUES ($($AnalysisResults['CriticalIssues'].Count) drives)**"
                        'weight' = 'Bolder'
                        'size' = 'Medium'
                        'color' = 'attention'
                    }
                )
                'spacing' = 'Medium'
            }
            
            ForEach ($critical in $AnalysisResults['CriticalIssues']) {
                $driveInfo = $critical.DiskInfo
                $issues = $critical.Issues -join "`n"
                $timeRemaining = If ($critical.EstimatedTimeRemaining) { $critical.EstimatedTimeRemaining } Else { 'Cannot determine' }
                
                # **ENHANCED**: Include wear information in drive details
                $driveFactSet = [System.Collections.Generic.List[PSObject]]::new()
                $driveFactSet.Add(@{ 'title' = '💽 **Drive**'; 'value' = $driveInfo.Model })
                $driveFactSet.Add(@{ 'title' = '🏭 **Manufacturer**'; 'value' = $driveInfo.Manufacturer })
                $driveFactSet.Add(@{ 'title' = '🔢 **Serial Number**'; 'value' = $driveInfo.SerialNumber })
                $driveFactSet.Add(@{ 'title' = '💾 **Type**'; 'value' = $driveInfo.DriveType })
                $driveFactSet.Add(@{ 'title' = '📏 **Capacity**'; 'value' = "$($driveInfo.SizeGB) GB" })
                $driveFactSet.Add(@{ 'title' = '🔌 **Interface**'; 'value' = $driveInfo.InterfaceType })
                
                # **NEW**: Add wear information if available
                If ($critical.WearInformation -and $critical.WearInformation['IsWearDataAvailable']) {
                    $wearDisplay = "$($critical.WearInformation['WearInterpretation']) (via $($critical.WearInformation['WearMethod']))"
                    $driveFactSet.Add(@{ 'title' = '🔧 **Wear Status**'; 'value' = $wearDisplay })
                } Else {
                    $driveFactSet.Add(@{ 'title' = '🔧 **Wear Status**'; 'value' = 'Data not available' })
                }
                
                $driveFactSet.Add(@{ 'title' = '⏰ **Est. Time Remaining**'; 'value' = $timeRemaining })
                $driveFactSet.Add(@{ 'title' = '🎯 **Recommended Action**'; 'value' = $critical.RecommendedAction })
                
                $criticalContainer['items'].Add(@{
                    'type' = 'Container'
                    'items' = @(
                        @{
                            'type' = 'FactSet'
                            'facts' = $driveFactSet.ToArray()
                        },
                        @{
                            'type' = 'TextBlock'
                            'text' = "**Issues Detected:**`n$issues"
                            'wrap' = $true
                            'spacing' = 'Small'
                        }
                    )
                    'style' = 'emphasis'
                    'spacing' = 'Small'
                })
            }
            
            $cardBody.Add($criticalContainer)
        }
        
        # **ENHANCED**: Warning issues section with wear information (similar structure)
        If ($AnalysisResults['WarningIssues'].Count -gt 0) {
            $warningContainer = @{
                'type' = 'Container'
                'style' = 'warning'
                'items' = [System.Collections.Generic.List[PSObject]]@(
                    @{
                        'type' = 'TextBlock'
                        'text' = "⚠️ **WARNING ISSUES ($($AnalysisResults['WarningIssues'].Count) drives)**"
                        'weight' = 'Bolder'
                        'size' = 'Medium'
                        'color' = 'warning'
                    }
                )
                'spacing' = 'Medium'
            }
            
            ForEach ($warning in $AnalysisResults['WarningIssues']) {
                $driveInfo = $warning.DiskInfo
                $issues = $warning.Issues -join "`n"
                $timeRemaining = If ($warning.EstimatedTimeRemaining) { $warning.EstimatedTimeRemaining } Else { 'Cannot determine' }
                
                # Include wear information in warning drives too
                $driveFactSet = [System.Collections.Generic.List[PSObject]]::new()
                $driveFactSet.Add(@{ 'title' = '💽 **Drive**'; 'value' = $driveInfo.Model })
                $driveFactSet.Add(@{ 'title' = '🏭 **Manufacturer**'; 'value' = $driveInfo.Manufacturer })
                $driveFactSet.Add(@{ 'title' = '🔢 **Serial Number**'; 'value' = $driveInfo.SerialNumber })
                $driveFactSet.Add(@{ 'title' = '💾 **Type**'; 'value' = $driveInfo.DriveType })
                $driveFactSet.Add(@{ 'title' = '📏 **Capacity**'; 'value' = "$($driveInfo.SizeGB) GB" })
                $driveFactSet.Add(@{ 'title' = '🔌 **Interface**'; 'value' = $driveInfo.InterfaceType })
                
                # Add wear information
                If ($warning.WearInformation -and $warning.WearInformation['IsWearDataAvailable']) {
                    $wearDisplay = "$($warning.WearInformation['WearInterpretation']) (via $($warning.WearInformation['WearMethod']))"
                    $driveFactSet.Add(@{ 'title' = '🔧 **Wear Status**'; 'value' = $wearDisplay })
                } Else {
                    $driveFactSet.Add(@{ 'title' = '🔧 **Wear Status**'; 'value' = 'Data not available' })
                }
                
                $driveFactSet.Add(@{ 'title' = '⏰ **Est. Time Remaining**'; 'value' = $timeRemaining })
                $driveFactSet.Add(@{ 'title' = '🎯 **Recommended Action**'; 'value' = $warning.RecommendedAction })
                
                $warningContainer['items'].Add(@{
                    'type' = 'Container'
                    'items' = @(
                        @{
                            'type' = 'FactSet'
                            'facts' = $driveFactSet.ToArray()
                        },
                        @{
                            'type' = 'TextBlock'
                            'text' = "**Issues Detected:**`n$issues"
                            'wrap' = $true
                            'spacing' = 'Small'
                        }
                    )
                    'style' = 'emphasis'
                    'spacing' = 'Small'
                })
            }
            
            $cardBody.Add($warningContainer)
        }
        
        # Healthy drives summary (same as before)
        If ($AnalysisResults['HealthyDrives'].Count -gt 0 -and ($AnalysisResults['CriticalIssues'].Count -gt 0 -or $AnalysisResults['WarningIssues'].Count -gt 0)) {
            $cardBody.Add(@{
                'type' = 'Container'
                'items' = @(
                    @{
                        'type' = 'TextBlock'
                        'text' = "✅ **Healthy Drives: $($AnalysisResults['HealthyDrives'].Count)**"
                        'weight' = 'Bolder'
                        'color' = 'good'
                        'spacing' = 'Medium'
                    },
                    @{
                        'type' = 'TextBlock'
                        'text' = ($AnalysisResults['HealthyDrives'] | ForEach-Object { "$($_.DiskInfo.Model) ($($_.DiskInfo.DriveType), $($_.DiskInfo.SizeGB) GB)" }) -join ', '
                        'wrap' = $true
                        'isSubtle' = $true
                        'spacing' = 'Small'
                    }
                )
            })
        }
        
        # **ENHANCED**: Footer with wear detection information
        $cardBody.Add(@{
            'type' = 'Container'
            'items' = @(
                @{
                    'type' = 'TextBlock'
                    'text' = '**ℹ️ About SMART Monitoring (v2.0 with Wear Detection)**'
                    'weight' = 'Bolder'
                    'spacing' = 'Medium'
                },
                @{
                    'type' = 'TextBlock'
                    'text' = 'This version includes multiple wear detection methods to address cases where PowerShell reports 0 wear for healthy drives. Wear data is obtained via PowerShell, alternative queries, or estimation methods. Critical issues require immediate attention. Warning issues should be monitored closely. Time estimates are based on industry research and should be used for planning only.'
                    'wrap' = $true
                    'isSubtle' = $true
                    'size' = 'Small'
                    'spacing' = 'Small'
                }
            )
        })
        
        # Create the complete adaptive card (same structure as before)
        $webhookPayload = @{
            'type' = 'message'
            'summary' = $mainTitle
            'attachments' = @(
                @{
                    'contentType' = 'application/vnd.microsoft.card.adaptive'
                    'content' = @{
                        '$schema' = 'http://adaptivecards.io/schemas/adaptive-card.json'
                        'type' = 'AdaptiveCard'
                        'version' = '1.5'
                        'msteams' = @{
                            'width' = 'Full'
                        }
                        'body' = $cardBody.ToArray()
                    }
                }
            )
        }
        
        # Convert to JSON with UTF-8 encoding for proper emoji support
        $jsonPayload = $webhookPayload | ConvertTo-Json -Depth 20
        $utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes($jsonPayload)
        
        # Send notification with retry logic
        $notificationResult = Invoke-OperationWithRetry -ScriptBlock {
            Invoke-RestMethod -Uri $WebhookUrl -Method 'POST' -Body $utf8Bytes -ContentType 'application/json; charset=utf-8' -ErrorAction Stop
        } -OperationDescription 'Teams adaptive card notification delivery'
        
        Write-Log -LogLevel 'SUCCESS' -Message 'Teams SMART health notification with wear information sent successfully'
        Return $true
        
    } Catch {
        Write-Log -LogLevel 'ERROR' -Message "Failed to send Teams notification: $($_.Exception.Message)"
        Write-Log -LogLevel 'ERROR' -Message "Stack trace: $($_.Exception.StackTrace)"
        Return $false
    }
}

#########################################################################################################################
#                                                   Main Execution                                                      #
#########################################################################################################################

Function Invoke-SmartHealthDetection {
    <#
    .SYNOPSIS
        Main function that orchestrates SMART health detection and notification process.
        
    .DESCRIPTION
        This function coordinates the entire SMART analysis workflow including disk enumeration,
        health analysis, and Teams notifications. Designed for Intune remediation with appropriate
        exit codes and comprehensive error handling.
        
    .OUTPUTS
        Exit code 0 for healthy drives, exit code 1 for detected issues
        
    .EXAMPLE
        Invoke-SmartHealthDetection
        
    .NOTES
        This is the main entry point for the Intune detection script. in v2.0 with
        improved drive type detection and updated SMART thresholds.
    #>
    [CmdletBinding()]
    Param()
    
    Try {
        Write-Log -LogLevel 'INFO' -Message '=== Starting SMART Disk Health Detection v2.0 for Intune ==='
        Write-Log -LogLevel 'INFO' -Message "Script version 2.0 - Analysis timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        
        # Gather system information
        $systemInfo = Get-SystemInformation
        Write-Log -LogLevel 'INFO' -Message "Analyzing system: $($systemInfo['ComputerName']) ($($systemInfo['Manufacturer']) $($systemInfo['Model']))"
        
        # Get disk information with drive type detection
        $diskInfo = Get-PhysicalDiskInformation
        If ($diskInfo.Count -eq 0) {
            Write-Log -LogLevel 'WARNING' -Message 'No physical disks found for analysis'
            Write-Output 'No physical disks found for SMART analysis'
            Exit 0  # No disks to analyze is not an error condition
        }
        
        Write-Log -LogLevel 'INFO' -Message "Found $($diskInfo.Count) physical disks for analysis"
        
        # Log drive types detected for troubleshooting
        ForEach ($disk in $diskInfo) {
            Write-Log -LogLevel 'INFO' -Message "Disk: $($disk.Model) - Type: $($disk.DriveType) - Interface: $($disk.InterfaceType) - Size: $($disk.SizeGB) GB"
        }
        
        # Get SMART status
        $smartStatus = Get-SmartStatus
        
        # Get detailed reliability counters (Windows 8/2012+)
        $reliabilityCounters = @()
        Try {
            $reliabilityCounters = Get-StorageReliabilityCounters
            Write-Log -LogLevel 'INFO' -Message "Retrieved detailed SMART attributes for $($reliabilityCounters.Count) drives"
        } Catch {
            Write-Log -LogLevel 'WARNING' -Message "Could not retrieve detailed SMART attributes: $($_.Exception.Message)"
        }
        
        # Perform comprehensive SMART analysis with drive type detection
        $analysisResults = Invoke-SmartAnalysis -DiskInfo $diskInfo -SmartStatus $smartStatus -ReliabilityCounters $reliabilityCounters
        
        # Log analysis summary
        Write-Log -LogLevel 'INFO' -Message "=== SMART Analysis Summary ==="
        Write-Log -LogLevel 'INFO' -Message "Overall Status: $($analysisResults['OverallStatus'])"
        Write-Log -LogLevel 'INFO' -Message "Total Drives: $($analysisResults['TotalDrives'])"
        Write-Log -LogLevel 'INFO' -Message "Critical Issues: $($analysisResults['CriticalIssues'].Count)"
        Write-Log -LogLevel 'INFO' -Message "Warning Issues: $($analysisResults['WarningIssues'].Count)"
        Write-Log -LogLevel 'INFO' -Message "Healthy Drives: $($analysisResults['HealthyDrives'].Count)"
        
        # Log drive type breakdown for analysis
        $driveTypeBreakdown = $diskInfo | Group-Object DriveType | ForEach-Object { "$($_.Name): $($_.Count)" }
        Write-Log -LogLevel 'INFO' -Message "Drive Types Detected: $($driveTypeBreakdown -join ', ')"
        
        # Send Teams notification if enabled and issues are detected
        $notificationSent = $false
        If ($script:SendTeamsNotification -and ($analysisResults['CriticalIssues'].Count -gt 0 -or $analysisResults['WarningIssues'].Count -gt 0)) {
            Write-Log -LogLevel 'INFO' -Message 'Sending Teams notification for detected issues'
            $notificationSent = Send-TeamsNotification -SystemInfo $systemInfo -AnalysisResults $analysisResults -WebhookUrl $script:WebhookUrl
            
            If ($notificationSent) {
                Write-Log -LogLevel 'SUCCESS' -Message 'Teams notification sent successfully'
            } Else {
                Write-Log -LogLevel 'ERROR' -Message 'Failed to send Teams notification'
            }
        } ElseIf (-not $script:SendTeamsNotification) {
            Write-Log -LogLevel 'INFO' -Message 'Teams notifications disabled in configuration'
        } Else {
            Write-Log -LogLevel 'INFO' -Message 'No issues detected - Teams notification not required'
        }
        
        # Determine exit code based on analysis results - CRITICAL for Intune detection scripts
        If ($analysisResults['CriticalIssues'].Count -gt 0 -or $analysisResults['WarningIssues'].Count -gt 0) {
            Write-Log -LogLevel 'WARNING' -Message 'SMART issues detected - Exiting with code 1 to trigger remediation workflow'
            
            # Output summary for Intune logging (max 2048 characters)
            $outputSummary = "SMART Health Issues Detected on $($systemInfo['ComputerName']): "
            $outputSummary += "Critical: $($analysisResults['CriticalIssues'].Count), "
            $outputSummary += "Warning: $($analysisResults['WarningIssues'].Count), "
            $outputSummary += "Total Drives: $($analysisResults['TotalDrives']) ($($driveTypeBreakdown -join ', ')). "
            
            If ($analysisResults['CriticalIssues'].Count -gt 0) {
                $criticalDrives = $analysisResults['CriticalIssues'] | ForEach-Object { "$($_.DiskInfo.Model) ($($_.DiskInfo.DriveType))" }
                $outputSummary += "Critical drives: $($criticalDrives -join ', '). "
            }
            
            If ($analysisResults['WarningIssues'].Count -gt 0) {
                $warningDrives = $analysisResults['WarningIssues'] | ForEach-Object { "$($_.DiskInfo.Model) ($($_.DiskInfo.DriveType))" }
                $outputSummary += "Warning drives: $($warningDrives -join ', '). "
            }
            
            $outputSummary += "Teams notification sent: $notificationSent. "
            $outputSummary += "Analysis completed: $($analysisResults['AnalysisTimestamp'])."
            
            # Ensure output doesn't exceed Intune's 2048 character limit
            If ($outputSummary.Length -gt 2048) {
                $outputSummary = $outputSummary.Substring(0, 2045) + '...'
            }
            
            Write-Output $outputSummary
            Write-Log -LogLevel 'INFO' -Message '=== SMART Detection Completed with Issues ==='
            Exit 1  # Trigger remediation workflow
            
        } Else {
            Write-Log -LogLevel 'SUCCESS' -Message 'All drives are healthy - Exiting with code 0'
            
            # Output success summary for Intune logging
            $outputSummary = "SMART Health Check Passed on $($systemInfo['ComputerName']): "
            $outputSummary += "All $($analysisResults['TotalDrives']) drives are healthy ($($driveTypeBreakdown -join ', ')). "
            $outputSummary += "Analysis completed: $($analysisResults['AnalysisTimestamp'])."
            
            Write-Output $outputSummary
            Write-Log -LogLevel 'INFO' -Message '=== SMART Detection Completed Successfully ==='
            Exit 0  # All drives healthy
        }
        
    } Catch {
        Write-Log -LogLevel 'ERROR' -Message "Critical error in SMART detection: $($_.Exception.Message)"
        Write-Log -LogLevel 'ERROR' -Message "Stack trace: $($_.Exception.StackTrace)"
        
        # Output error for Intune logging
        $errorOutput = "SMART Detection Error on $($env:COMPUTERNAME): $($_.Exception.Message). Check logs for details."
        If ($errorOutput.Length -gt 2048) {
            $errorOutput = $errorOutput.Substring(0, 2045) + '...'
        }
        
        Write-Output $errorOutput
        Write-Log -LogLevel 'INFO' -Message '=== SMART Detection Failed ==='
        Exit 1  # Exit with error to trigger investigation
    }
}

#########################################################################################################################
#                                              Script Execution Entry Point                                             #
#########################################################################################################################

# Initialize logging
Try {
    If (-not (Test-Path -Path $script:LogPath)) {
        New-Item -Path $script:LogPath -ItemType File -Force | Out-Null
    }
    Write-Log -LogLevel 'INFO' -Message "SMART Detection script v2.0 started - PowerShell version: $($PSVersionTable.PSVersion)"
} Catch {
    Write-Warning "Failed to initialize logging: $($_.Exception.Message)"
}

# Validate PowerShell version
If ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Log -LogLevel 'ERROR' -Message "PowerShell 5.0 or later required. Current version: $($PSVersionTable.PSVersion)"
    Write-Output "PowerShell 5.0 or later required for SMART detection"
    Exit 1
}

# Validate webhook URL if notifications are enabled
If ($script:SendTeamsNotification) {
    If ([String]::IsNullOrWhiteSpace($script:WebhookUrl) -or $script:WebhookUrl -eq 'https://your-tenant.webhook.office.com/webhookb2/your-webhook-path-here') {
        Write-Log -LogLevel 'WARNING' -Message 'Teams notifications enabled but webhook URL not configured - Disabling notifications'
        $script:SendTeamsNotification = $false
    } Else {
        Write-Log -LogLevel 'INFO' -Message 'Teams notifications enabled and webhook URL configured'
    }
} Else {
    Write-Log -LogLevel 'INFO' -Message 'Teams notifications disabled in configuration'
}

# Execute main detection function
Invoke-SmartHealthDetection