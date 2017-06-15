param(
    [Parameter(Mandatory = $true)]
    [String]$Base64Cert,
    [Parameter(Mandatory = $true)]
    [String]$ExportFilename
    )

function Export-Certificate {
[CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory = $true)]
        [IO.FileInfo]$OutputFile,
        [switch]$IncludeAllCerts
    )
    $certs = New-Object Security.Cryptography.X509Certificates.X509Certificate2Collection
    if ($IncludeAllCerts) {
        $chain = New-Object Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.RevocationMode = "NoCheck"
        [void]$chain.Build($Certificate)
        $chain.ChainElements | ForEach-Object {[void]$certs.Add($_.Certificate)}
        $chain.Reset()
    } else {
        [void]$certs.Add($Certificate)
    }
    Set-Content -Path $OutputFile.FullName -Value $certs.Export("pkcs7") -Encoding Byte
}

# # # #


$X509Cert = [Security.Cryptography.X509Certificates.X509Certificate2]([System.Convert]::FromBase64String($Base64Cert))

Export-Certificate -Certificate $X509Cert -OutputFile $ExportFilename -IncludeAllCerts 
