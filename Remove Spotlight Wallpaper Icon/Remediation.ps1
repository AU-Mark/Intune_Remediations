$RegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
$RegValue = "{2cc5ca98-6485-489a-920e-b3e88a6ccce3}"

Try {
    New-ItemProperty -Path $RegPath -Name $RegValue -Value 1 -PropertyType DWord  
    Write-Output "Windows Spotlight desktop icon removed successfully!"
    Exit 0
} Catch {
    Write-Output "An error occured - Err Line: $($_.InvocationInfo.ScriptLineNumber) Err Name: $($_.Exception.GetType().FullName) Err Msg: $($_.Exception.Message)"
    Exit 1
}
