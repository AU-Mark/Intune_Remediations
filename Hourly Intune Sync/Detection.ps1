# This script will make the device sync to Intune every time it is run. You decide when setting the schedule in Intune how often this will occur.
Try {
    # Get last time PushLaunch scheduled task was executed
    $PushInfo = Get-ScheduledTask | Where-Object {$_.TaskName -eq 'PushLaunch'} | Get-ScheduledTaskInfo
    $LastPush = $PushInfo.LastRunTime

    # Get the current datetime
    $CurrentTime=(GET-DATE)

    # Variable used to determine if we could calculate the TimeSpan difference or not
    $NoTimeDiff = 0

    Try {
        # Calculate the time difference between the current datetime and the last push time
        $TimeDiff = New-TimeSpan -Start $LastPush -End $CurrentTime
    } Catch [System.Management.Automation.ParameterBindingException] {
        # Couldnt calculate the time difference so set the variable to 1
        $NoTimeDiff = 1
    }

    # Run the scheduled task!
    Get-ScheduledTask | Where-Object {$_.TaskName -eq 'PushLaunch'} | Start-ScheduledTask

    # If we didnt run into an error, show the time difference when the last time it was synced
    If ($NoTimeDiff -eq 0) {
        Write-Output "Sync Started! Last sync was $($TimeDiff.Hours) hours and $($TimeDiff.Minutes) minutes ago"
    # Else just show that we couldnt calculate the time difference
    } Else {
        Write-Output "Sync Started! The last runtime of the PushLaunch task could not be calculated!"
    }

    # Exit the script without errors
    Exit 0
} Catch {
    # Catch and report the error
    Write-Error "Err Line: $($_.InvocationInfo.ScriptLineNumber) Err Name: $($_.Exception.GetType().FullName) Err Msg: $($_.Exception.Message)"
    Exit 1
}
