<#
.SYNOPSIS
  Backs up the bitlocker key for the system drive to Intune detection script output
.DESCRIPTION
  
.INPUTS
  None
.OUTPUTS
  None
.NOTES
  Version:        1.0
  Author:         Mark Newton
  Creation Date:  06/10/2023
  Purpose/Change: Initial script development

  Version:        1.1
  Author:         Mark Newton
  Creation Date:  07/17/2023
  Purpose/Change: Disable analyze component store with DISM and fixed issues with SFC not outputting text correctly due to the utility's character encoding.
.EXAMPLE
  PowerShell.exe -ExecutionPolicy Bypass -File Detection.ps1
#>

Try {
    # Get the drive containing the system partition (Uses substring to get only drive letter and colon)
    $SystemPartition = ($Env:SystemRoot).Substring(0,2)

    # Get Bitlocker status for system drive
    $BLInfo = Get-Bitlockervolume -MountPoint $SystemPartition

    # If Bitlocker is turned on
    If ($BLInfo.ProtectionStatus -eq "On") {
        # If System drive is fully encrypted
        If ($BLInfo.VolumeStatus -eq "FullyEncrypted") {
            # Get the recovery key for the system drive
            $RecoveryKey = ((Get-BitLockerVolume -MountPoint $SystemPartition).KeyProtector).RecoveryPassword
            # Write the key to output and exit with no errors
            If ($Null -ne $RecoveryKey) {
                Write-Output $RecoveryKey
                Exit 0
            # Recovery key was not found even though the drive is encrypted with Bitlocker. Exit with an error.
            } Else {
                Write-Output "Recovery key not found!"
                Exit 1
            }
        # Bitlocker is in progress of encrypting and will update with the key on a subsequent run of the script
        } ElseIf ($BLInfo.VolumeStatus -eq "Progress") {
                Write-Output "Bitlocker encryption at $($BLInfo.EncryptionPercentage)%. Key will be uploaded once complete."
                Exit 0
        # Bitlocker is on but in an unknown volume status. Report the status and exit with error.
        } Else {
            Write-Output "Bitlocker On; Unknown Volume Status: $($BLInfo.VolumeStatus)"
            Exit 1
        }
    # Bitlocker is not enabled. Check the TPM status on the device.
    } Else {
        # Get the TPM Status
        $TPM = Get-Tpm
        # TPM module present
        If ($TPM.TpmPresent) {
            # TPM module activated but bitlocker is off or TPM is imcompatible with bitlocker. Write output and exit with error.
            If ($TPM.TpmActivated) {
                Write-Output "Bitlocker Off or TPM incompatible"
                Exit 1
            # TPM module is not activated on the device. Write output and exit with error.
            } Else {
                Write-Output "TPM module not activated!"
                Exit 1
            }
        # No TPM module was found. Write output and exit with error.
        } Else {
            Write-Output "No TPM module found!"
            Exit 1
        }
    }
} Catch {
    # Error occured while trying to retrieve the bitlocker key and/or TPM status. Write error info to output and exit.
    Write-Output "An error occured - Err Line: $($_.InvocationInfo.ScriptLineNumber) Err Name: $($_.Exception.GetType().FullName) Err Msg: $($_.Exception.Message)"
    Exit 1
}
