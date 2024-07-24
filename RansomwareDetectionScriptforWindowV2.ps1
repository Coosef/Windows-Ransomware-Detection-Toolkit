# Ransomware Detection Script for Windows
# WARNING: This is a basic script. For comprehensive protection, use a professional antivirus solution.
Set-ExecutionPolicy RemoteSigned
# Define suspicious file extensions commonly used by ransomware
$suspiciousExtensions = ".cry", ".crypto", ".darkness", "*enc*", "*.exx", "*.kb15", "*.kraken", "*.locked", "*.nochance", 
                        ".0x0", ".02", ".725", ".1999", ".1cbu1", ".1txt", ".2ed2", ".73i87A", ".726", ".777", ".7h9r", 
                        ".7z.encrypted", ".7zipper", ".8c7f", ".8lock8", ".911", ".a19", ".a5zfn", ".aaa", ".abc", ".adk",
                        ".adr", ".AES", ".AES256", ".aes_ni", ".aes_ni_gov", ".aes_ni_0day", ".AESIR", ".AFD", ".aga", 
                        ".alcatraz", ".Aleta", ".amba", ".amnesia", ".angelamerkel", ".AngleWare", ".antihacker2017", ".ap19",
                        ".atlas", ".arena", ".axx", ".B6E1", ".BarRax", ".bart", ".bart.zip", ".better_call_saul", ".bip", 
                        ".bitstak", ".bitkangoroo", ".bleep", ".bleepYourFiles", ".bloc", ".blocatto", ".block", ".braincrypt",
                        ".breaking_bad", ".bript", ".btc", ".btcbtcbtc", ".btc-help-you", ".cancer", ".canihelpyou", ".cbf", 
                        ".ccc", ".CCCRRRPPP", ".cerber", ".cerber2", ".cerber3", ".checkdiskenced", ".chifrator@qq_com", ".CHIP",
                        ".cifgksaffsfyghd", ".clf", ".cnc", ".code", ".coded", ".comrade", ".coverton", ".crashed", ".crime", 
                        ".crinf", ".criptiko", ".criptokod", ".cripttt", ".crjoker", ".crptrgr", ".CRRRT", ".cry", ".cry_",
                        ".cryp1", ".crypt", ".crypt38", ".crypted", ".crypted_file", ".crypto", ".crypto*", ".cryptolocker",
                        ".cryptolocker*", ".CRYPTOSHIEL", ".CRYPTOSHIELD", ".CryptoTorLocker2015!", ".cryptowall", ".cryptowin",
                        ".crypz", ".CrySiS", ".ctb1", ".ctb2", ".ctbl", ".CTBL", ".czvxce", ".d4nk", ".da_vinci_code", ".dale", 
                        ".damage", ".darkness", ".darkcry", ".dCrypt", ".decrypt2017", ".ded", ".deria", ".dharma", ".disappeared",
                        ".diablo6", ".domino", ".doomed", ".dxxd", ".dyatel@qq_com", ".ecc", ".edgel", ".enc", ".encedRSA",
                        ".EnCiPhErEd", ".encmywork", ".encoderpass", ".ENCR", ".encrypt", ".encrypted", ".EnCrYpTeD", ".encryptedAES",
                        ".encryptedRSA", ".encryptedyourfiles", ".enigma", ".epic", ".evillock", ".exotic", ".exte", ".exx", ".ezz",
                        ".fantom", ".fear", ".FenixIloveyou!!", ".file0locked", ".filegofprencrp", ".fileiscryptedhard", ".filock", 
                        ".firecrypt", ".flyper", ".frtrss", ".fs0ciety", ".fuck", ".Fuck_You", ".fucked", ".FuckYourData", ".fun",
                        ".gefickt", ".gembok", ".globe", ".goforhelp", ".good", ".gruzin@qq_com", ".gryphon", ".GSupport*", ".GWS",
                        ".HA3", ".hairullah@inbox.lv", ".hakunamatata", ".hannah", ".haters", ".happyday", ".happydayzz", ".happydayzzz",
                        ".hb15", ".helpdecrypt@ukr*.net", ".helpmeencedfiles", ".herbst", ".help", ".hnumkhotep", ".howcanihelpusir",
                        ".hush", ".hydracrypt*", ".iaufkakfhsaraf", ".ifuckedyou", ".iloveworld", ".infected", ".info", ".isis", 
                        ".ipYgh", ".iwanthelpuuu", ".jaff", ".JUST", ".justbtcwillhelpyou", ".karma", ".kb15", ".kencf", ".keepcalm",
                        ".kernel_complete", ".kernel_pid", ".kernel_time", ".keybtc@inbox_com", ".KEYH0LES", ".KEYZ", "keemail.me",
                        ".killedXXX", ".kirked", ".kimcilware", ".KKK", ".kk", ".korrektor", ".kostya", ".kr3", ".kraken", ".kratos",
                        ".kyra", ".lechiffre", ".L0CKED", ".L0cked", ".lambda_l0cked", ".LeChiffre", ".legion", ".lesli", ".letmetrydecfiles",
                        ".lock*", ".lock93", ".locked", ".Locked-by-Mafia", ".locked-mafiaware", ".locklock", ".locky", ".LOL!", ".loprt",
                        ".lovewindows", ".lukitus", ".madebyadam", ".magic", ".maktub", ".malki", ".maya", ".merry", ".micro", ".MRCR1", 
                        ".nalog@qq_com", ".nemo-hacks.at.sigaint.org", ".no_more_ransom", ".nochance", ".nochance*", ".nolvalid", 
                        ".noproblemwedecfiles", ".notfoundrans", ".nuclear55", ".nuclear", ".obleep", ".odcodc", ".odin", ".OMG!", ".omg*",
                        ".only-we_can_help_you", ".onion.to._", ".oops", ".openforyou@india.com", ".oplata@qq.com", ".oshit", ".osiris", 
                        ".otherinformation", ".oxr", ".p5tkjw", ".pablukcrypt", ".padcrypt", ".paybtcs", ".paym", ".paymrss", ".payms", 
                        ".paymst", ".paymts", ".payransom", ".payrms", ".payrmts", ".pays", ".paytounlock", ".pdcr", ".PEGS1", ".perl", 
                        ".pizda@qq_com", ".PoAr2w", ".porno", ".potato", ".powerfulldecrypt", ".powned", ".pr0tect", ".purge", ".pzdc", 
                        ".R.i.P", ".r16m*", ".R16M01D05", ".r3store", ".R4A", ".R5A", ".r5a", ".RAD", ".RADAMANT", ".raid10", ".RARE1", 
                        ".razy", ".RDM", ".rdmk", ".realfs0ciety@sigaint.org.fs0ciety", ".rekt", ".relock@qq_com", ".reyptson", ".remind", 
                        ".rip", ".RMCM1", ".rmd", ".rnsmwr", ".rokku", ".rrk", ".RSNSlocked", ".RSplited", ".sage", ".salsa222", ".sanction",
                        ".scl", ".SecureCrypted", ".serpent", ".sexy", ".shino", ".shit", ".sifreli", ".Silent", ".sport", ".stn", ".supercrypt",
                        ".surprise", ".szf", ".t5019", ".TheTrumpLockerf", ".TheTrumpLockerfp", ".theworldisyours", ".thor", ".toxcrypt", 
                        ".troyancoder@qq_com", ".trun", ".trmt", ".ttt", ".tzu", ".uk-dealer@sigaint.org", ".unavailable", ".unlockvt@india.com",
                        ".vault", ".vbransom", ".vekanhelpu", ".velikasrbija", ".venusf", ".Venusp", ".versiegelt", ".VforVendetta", ".vindows",
                        ".viki", ".visioncrypt", ".vvv", ".vxLock", ".wallet", ".wcry", ".weareyourfriends", ".weencedufiles", ".wflx", ".wlu", 
                        ".Where_my_files.txt", ".Whereisyourfiles", ".windows10", ".wnx", ".WNCRY", ".wncryt", ".wnry", ".wowreadfordecryp", 
                        ".wowwhereismyfiles", ".wuciwug", ".www", ".xcri", ".xdata", ".xort", ".xrnt", ".xrtn", ".xtbl", ".xxx", ".xyz", ".ya.ru", 
                        ".yourransom", ".Z81928819", ".zc3791", ".zcrypt", ".zendr4", ".zepto", ".zorro", ".zXz", ".zyklon", ".zzz", ".zzzzz",
                        ".aaa", ".abc", ".AES256", ".chifrator@qq_com", ".darkness", ".Encrypted", ".encryptedped", ".gruzin@qq_com", ".gws", 
                        ".ha3", ".helpdecrypt@ukr_net", ".KEYHOLES", ".KEYZ", ".kkk", ".one-we_can-help_you", ".oor", ".oplata@qq_com", ".R4A",
                        ".RRK", ".ryp", ".vscrypt", ".zzz", ".wncry", ".wncrypt", ".___xratteamLucked", ".__AiraCropEncrypted!", "._AiraCropEncrypted",
                        "._read_thi$_file*", ".31392E30362E32303136_[ID-KEY]_LSBJ1"


# Define common ransomware note names
$ransomNoteNames = "README.txt", "_readme.txt", "DECRYPT_INSTRUCTIONS.txt" # Add more names as needed

# Define log file path on Desktop
$userDesktop = [Environment]::GetFolderPath("Desktop")
$logFile = Join-Path $userDesktop "RansomwareDetectionLog.txt"

# Clear previous log file content
if (Test-Path $logFile) {
    Clear-Content $logFile
}

# Function to search for suspicious files and write findings to a log file
function Search-ForSuspiciousFiles {
    param(
        [string]$path,
        [string[]]$extensions,
        [string[]]$noteNames
    )

    Write-Host "Scanning for suspicious files in $path"
    Add-Content $logFile "Scanning for suspicious files in $path"

    # Search for suspicious file extensions
    foreach ($ext in $extensions) {
        $files = Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue -Filter "*$ext"
        foreach ($file in $files) {
            $message = "Suspicious file found: $($file.FullName)"
            Write-Host $message
            Add-Content $logFile $message
        }
    }

    # Search for ransom notes
    foreach ($noteName in $noteNames) {
        $notes = Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue -Filter $noteName
        foreach ($note in $notes) {
            $message = "Ransom note found: $($note.FullName)"
            Write-Host $message
            Add-Content $logFile $message
        }
    }
}

# Execute the search
Search-ForSuspiciousFiles -path $driveToScan -extensions $suspiciousExtensions -noteNames $ransomNoteNames

Write-Host "Scan complete. Review the log at $logFile for findings. Please take further action if any suspicious files or notes are found."