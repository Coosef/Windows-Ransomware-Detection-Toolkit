# Ransomware Detection Script for Windows
# WARNING: This is a basic script. For comprehensive protection, use a professional antivirus solution.
Set-ExecutionPolicy RemoteSigned
# Define suspicious file extensions commonly used by ransomware
$suspiciousExtensions = ".lockbit", ".abcd", ".locked" # Add more extensions as needed

# Define common ransomware note names
$ransomNoteNames = "README.txt", "_readme.txt", "DECRYPT_INSTRUCTIONS.txt" # Add more names as needed

# Scan the system drive, adjust the drive letter as necessary
$driveToScan = "C:\"

# Function to search for suspicious files
function Search-ForSuspiciousFiles {
    param(
        [string]$path,
        [string[]]$extensions,
        [string[]]$noteNames
    )

    Write-Host "Scanning for suspicious files in $path"

    # Search for suspicious file extensions
    foreach ($ext in $extensions) {
        $files = Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue -Filter "*$ext"
        foreach ($file in $files) {
            Write-Host "Suspicious file found: $($file.FullName)"
        }
    }

    # Search for ransom notes
    foreach ($noteName in $noteNames) {
        $notes = Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue -Filter $noteName
        foreach ($note in $notes) {
            Write-Host "Ransom note found: $($note.FullName)"
        }
    }
}

# Execute the search
Search-ForSuspiciousFiles -path $driveToScan -extensions $suspiciousExtensions -noteNames $ransomNoteNames

Write-Host "Scan complete. Review the findings above. Please take further action if any suspicious files or notes are found."
