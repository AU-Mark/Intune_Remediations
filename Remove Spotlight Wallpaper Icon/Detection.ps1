Function Test-Registry {
    param(
        [Alias("PSPath")]
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [String]$Path
        ,
        [Parameter(Position = 1, Mandatory = $false)]
        [String]$Name
        ,
        [Switch]$PassThru
    ) 

    process {
        if (Test-Path $Path) {
            $Key = Get-Item -LiteralPath $Path
			If ($Name) {
				if ($Key.GetValue($Name, $null) -ne $null) {
					if ($PassThru) {
						Get-ItemProperty $Path $Name
					} else {
						$true
					}
				} else {
					$false
				}
            } else {
				$true
			}
        } else {
            $false
        }
    }
}

$RegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
$RegValue = "{2cc5ca98-6485-489a-920e-b3e88a6ccce3}"

If (!(Test-Registry -Path $RegPath -Name $RegValue -PassThru)) {
    Write-Output "Windows Spotlight desktop icon visible on this workstation. Remediation required."
    Exit 1
}  Else {
    Write-Output "Windows Spotlight desktop icon is hidden. No remediation required."
    Exit 0
}
