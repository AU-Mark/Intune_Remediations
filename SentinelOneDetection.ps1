Function Get-InstalledApplication {
    <#
    .SYNOPSIS
    Retrieves installed applications from local or remote computers.

    .DESCRIPTION
    This function queries the Windows Registry to retrieve information about installed applications
    on local or remote computers. It searches both 32-bit and 64-bit application registries and
    returns detailed information about each installed application. The function supports filtering
    by application name, publisher, and identifying number (GUID).

    .PARAMETER ComputerName
    Specifies the name of one or more computers from which to retrieve installed application information.
    Default value is the local computer name.

    .PARAMETER Properties
    Specifies additional registry properties to retrieve for each application. Use '*' to retrieve all available properties.

    .PARAMETER IdentifyingNumber
    Filters results by the application's identifying number (GUID).

    .PARAMETER Name
    Filters results by the application's display name. Supports wildcards.

    .PARAMETER Publisher
    Filters results by the application's publisher. Supports wildcards.

    .EXAMPLE
    Get-InstalledApplication

    Returns all installed applications on the local computer.

    .EXAMPLE
    Get-InstalledApplication -ComputerName 'Server01','Server02' -Name 'Microsoft*'

    Returns all installed applications that have a name starting with 'Microsoft' on the computers Server01 and Server02.

    .EXAMPLE
    Get-InstalledApplication -Properties '*'

    Returns all installed applications on the local computer with all available registry properties.

    .EXAMPLE
    Get-InstalledApplication -IdentifyingNumber '{909B7ACD-FC28-4B85-8F6B-CD3FE8B29828}'

    Returns the specific application with the provided GUID.

    .OUTPUTS
    PSCustomObject with properties including Name, Version, Publisher, InstallDate, UninstallString, and more.

    .NOTES
    Author: AU-Mark
    Last Modified: 04/28/2025
    Version: 1.1
    #>
    [CmdletBinding()]
    Param(
        [Parameter(
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [String[]]$ComputerName = $ENV:COMPUTERNAME,

        [Parameter(Position = 1)]
        [String[]]$Properties,

        [Parameter(Position = 2)]
        [String]$IdentifyingNumber,

        [Parameter(Position = 3)]
        [String]$Name,

        [Parameter(Position = 4)]
        [String]$Publisher
    )

    # Helper function to determine if CPU architecture is x86
    Function Test-CpuIsX86 {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory = $true)]
            [Microsoft.Win32.RegistryKey]$HklmHive
        )
        
        # Define the registry path for system environment variables
        $RegPath = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
        $Key = $HklmHive.OpenSubKey($RegPath)

        # Check if we can access the registry key
        If (!$Key) {
            Write-Warning "Unable to access registry key: $($RegPath)"
            Return $false
        }

        # Get the processor architecture value and check if it's x86
        $CpuArch = $Key.GetValue('PROCESSOR_ARCHITECTURE')
        Return $CpuArch -eq 'x86'
    }

    # Process each computer in the ComputerName parameter
    ForEach ($Computer in $ComputerName) {
        # Define registry paths for installed applications (both 32-bit and 64-bit)
        $RegPaths = @(
            'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
            'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
        )

        Try {
            Write-Verbose "Connecting to registry on computer: $($Computer)"
            
            # Open remote registry connection to the target computer
            $Hive = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey(
                [Microsoft.Win32.RegistryHive]::LocalMachine, 
                $Computer
            )
            
            # Verify the registry connection was successful
            If (!$Hive) {
                Write-Warning "Failed to connect to registry on computer: $($Computer)"
                Continue
            }
            
            # Check CPU architecture and adjust registry paths accordingly for x86 systems
            If (Test-CpuIsX86 -HklmHive $Hive) {
                Write-Verbose "Detected x86 architecture on $($Computer), skipping Wow6432Node"
                $RegPaths = $RegPaths[0]
            }

            # Process each registry path (32-bit and 64-bit uninstall locations)
            ForEach ($Path in $RegPaths) {
                $Key = $Hive.OpenSubKey($Path)
                
                # Skip if the registry path doesn't exist
                If (!$Key) {
                    Write-Verbose "Registry path not found: $($Path) on $($Computer)"
                    Continue
                }
                
                # Get all subkeys (each represents an installed application)
                $SubKeyNames = $Key.GetSubKeyNames()
                Write-Verbose "Found $($SubKeyNames.Count) entries in $($Path) on $($Computer)"
                
                # Process each installed application subkey
                ForEach ($SubKey in $SubKeyNames) {
                    # Filter by IdentifyingNumber (GUID) if specified
                    If ($PSBoundParameters.ContainsKey('IdentifyingNumber')) {
                        $NormalizedSubKey = $SubKey.TrimStart('{').TrimEnd('}')
                        $NormalizedIdentifyingNumber = $IdentifyingNumber.TrimStart('{').TrimEnd('}')
                    
                        If ($NormalizedSubKey -ne $NormalizedIdentifyingNumber -and $SubKey -ne $IdentifyingNumber) {
                            Continue
                        }
                    }
                    
                    # Open the specific application's registry subkey
                    $SubKeyObj = $Key.OpenSubKey($SubKey)
                    If (!$SubKeyObj) {
                        Write-Verbose "Unable to open subkey: $($SubKey)"
                        Continue
                    }
                    
                    # Initialize ordered hashtable for output object properties
                    $OutHash = [Ordered]@{}
                    
                    # Get application basic information - DisplayName is required
                    $AppName = $SubKeyObj.GetValue('DisplayName')
                    
                    # Skip entries without a display name (not real applications)
                    If (!$AppName) {
                        Continue
                    }
                    
                    # Filter by application name if specified (supports wildcards)
                    If ($PSBoundParameters.ContainsKey('Name')) {
                        If ($AppName -notlike $Name) {
                            Continue
                        }
                    }
                    
                    # Retrieve standard application properties from registry
                    $AppVersion = $SubKeyObj.GetValue('DisplayVersion')
                    $AppEstimatedSize = $SubKeyObj.GetValue('EstimatedSize')
                    $AppInstallDate = $SubKeyObj.GetValue('InstallDate')
                    $AppInstallLocation = $SubKeyObj.GetValue('InstallLocation')
                    $AppInstallSource = $SubKeyObj.GetValue('InstallSource')
                    $AppUninstallString = $SubKeyObj.GetValue('UninstallString')
                    $AppPublisher = $SubKeyObj.GetValue('Publisher')
                    
                    # Filter by publisher if specified (supports wildcards)
                    If ($PSBoundParameters.ContainsKey('Publisher')) {
                        If ($AppPublisher -notlike $Publisher) {
                            Continue
                        }
                    }
                    
                    # Handle additional properties if requested
                    If ($PSBoundParameters.ContainsKey('Properties')) {
                        If ($Properties -eq '*') {
                            # Retrieve all available registry properties
                            ForEach ($ValueName in $SubKeyObj.GetValueNames()) {
                                Try {
                                    $Value = $SubKeyObj.GetValue($ValueName)
                                    If ($null -ne $Value) {
                                        $OutHash[$ValueName] = $Value
                                    }
                                } Catch {
                                    Write-Warning "Error retrieving value '$($ValueName)' for subkey '$($SubKey)': $($_.Exception.Message)"
                                }
                            }
                        } Else {
                            # Retrieve only specified properties
                            ForEach ($Prop in $Properties) {
                                $Value = $SubKeyObj.GetValue($Prop)
                                If ($null -ne $Value) {
                                    $OutHash[$Prop] = $Value
                                }
                            }
                        }
                    }
                    
                    # Add standard properties to the output object
                    $OutHash['Name'] = $AppName
                    $OutHash['Version'] = $AppVersion
                    $OutHash['EstimatedSize'] = $AppEstimatedSize
                    $OutHash['InstallDate'] = $AppInstallDate
                    $OutHash['InstallLocation'] = $AppInstallLocation
                    $OutHash['InstallSource'] = $AppInstallSource
                    $OutHash['IdentifyingNumber'] = $SubKey
                    $OutHash['Publisher'] = $AppPublisher
                    $OutHash['UninstallString'] = $AppUninstallString
                    $OutHash['ComputerName'] = $Computer
                    $OutHash['Path'] = $SubKeyObj.ToString()
                    
                    # Convert ordered hashtable to PSObject and output to pipeline
                    New-Object -TypeName PSObject -Property $OutHash
                }
            }
        } Catch {
            $ErrorMsg = "Error processing computer '$($Computer)': $($_.Exception.Message)"
            Write-Error $ErrorMsg
        }
    }

    Write-Verbose "Completed retrieving installed applications."
}

$Sentinel = Get-InstalledApplication -Name "*Sentinel*"

If ([System.Version]$Sentinel.Version -ge 24.2.471) {
    # App was found to be installed and at least the minimum version was detected
    Write-Output "SenintelOne is installed and at least version 24.1.6.313"
    Exit 0
} Else {
    # App was not found to be installed
    Write-Output "SenintelOne was not found"
    Exit 1
}
