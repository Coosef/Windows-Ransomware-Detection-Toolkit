/*
  Windows Ransomware Detection Toolkit - sample YARA rule.

  OPTIONAL. YARA scanning only runs if the `yara` command-line tool is installed
  AND at least one .yar/.yara file exists in this folder. If yara is not present
  the toolkit simply skips this layer (no dependency required).

  Install yara:  Windows -> https://github.com/VirusTotal/yara/releases
                 Linux   -> sudo apt install yara     (Debian/Ubuntu)
                 macOS   -> brew install yara

  Drop your own vendor/community .yar rules in this folder to extend coverage.
*/

rule Ransom_Note_Generic
{
    meta:
        description = "Generic ransom-note wording"
        severity    = "high"
    strings:
        $a = "your files have been encrypted" nocase
        $b = "all your files are encrypted"   nocase
        $c = "decrypt your files"             nocase
        $d = "buy decryptor"                  nocase
        $e = ".onion"                          nocase
        $f = "bitcoin"                         nocase
        $g = "your network has been"          nocase
    condition:
        2 of them
}
