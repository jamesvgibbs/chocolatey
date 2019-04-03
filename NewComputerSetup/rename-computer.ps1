workflow rename-localsystem {
    param (
        [string]$newname
    )
    
    Rename-Computer -Newname $newname -Force -Passthru
    
    Restart-Computer
}

# rename-localsystem -newname W12SUS
