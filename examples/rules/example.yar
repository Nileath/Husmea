// Reglas YARA de ejemplo para husmea (--yara-rules examples/rules)
// Son reglas genéricas de demostración. Para uso real, utilice colecciones mantenidas
// como YARA Forge (https://yarahq.github.io/) o las reglas de su proveedor de seguridad.

rule EICAR_Test_File
{
    meta:
        description = "Fichero de prueba antivirus EICAR"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        filesize < 256 and $eicar
}

rule Suspicious_PowerShell_Downloader
{
    meta:
        description = "Script con descarga y ejecución de código remoto mediante PowerShell"
    strings:
        $a1 = "DownloadString" ascii wide nocase
        $a2 = "DownloadFile" ascii wide nocase
        $a3 = "Invoke-WebRequest" ascii wide nocase
        $b1 = "IEX" ascii wide
        $b2 = "Invoke-Expression" ascii wide nocase
        $b3 = "FromBase64String" ascii wide nocase
    condition:
        filesize < 2MB and 1 of ($a*) and 1 of ($b*)
}
