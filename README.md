# SecretServerSecretStealer

<img src="https://raw.githubusercontent.com/denandz/SecretServerSecretStealer/master/images/logo.png" width="210px" height="206px">

SecretServerSecretStealer is a powershell script that allows for the decryption of passwords (and other items) stored within a Thycotic Secret Server installation. Two methods are exposed, Invoke-SecretDecrypt and Invoke-SecretStealer.

Invoke-SecretDecrypt requires you to manually pass the various data needed to decrypt a single secret (see Decryption). Invoke-SecretStealer is designed to be run on a Thycotic Secret Server machine itself, and takes only the web root as a parameter. The SecretStealer will decrypt the database configuration and connect to the application's db. All relevant information is extracted, and all secrets decrypted.


## Execution

Invoke-SecretStealer should be executed on the Secret Server itself, for example:

```PowerShell
Invoke-SecretStealer -WebRoot C:\inetpub\wwwroot\SecretServer
```

<img src="https://raw.githubusercontent.com/denandz/SecretServerSecretStealer/master/images/invoke-secretstealer.png">

Invoke-SecretDecrypt can be executed to decrypt a specific item. You need to retrieve the following fields from the DB: tbSecret.key, tbSecret.IvMEK, tbSecretItem.IV and tbSecretItem.ItemValue. Be sure to corellate the SecretID between these entries, as the intermediate keys are unique to a specific SecretID. The following SQL may be used to dump all of the relevant information, along with some other auxilliary data:

```sql
select s.SecretName, f.SecretFieldName, s.[Key], s.IvMEK, i.ItemValue, i.IV from tbSecretItem as i JOIN tbSecret as s ON (s.SecretID = i.SecretID) JOIN tbSecretField as f on (i.SecretFieldID = f.SecretFieldID)
```

After retrieving the above, you can run Invoke-SecretDecrypt

```PowerShell
Invoke-SecretDecrypt -Item 9993c5097491ba2b42a10b9a9b7a6ab7239b107337c348086eeb5f5b29c76f33 -ItemIV CF4C2D4F7FA432D64D9712212A06EEA9 -IVMek 6080667306DA295A75E22667E9AD0376 -Key 5C195A500A3BF87C29163A52AC4EA2CFF6C5B69407B6F91A7C7B100B6D20121AAFD052C11B13D542EA2F42137258C2EF -EncryptionConfig C:\whatever\encryption.config
```

## Decryption

The Thycotic Secret Server essentially works on the principle of 'more crypto, more better'. Every entry has multiple items, such as a password, name, url, etcetera. Each of these items are encrypted with an intermediate key that is specific to that entry. That intermediate key is encrypted by a master key, which is unique to each installation and stored in the encryption.config file. The encryption.config file itself is a binary serialized object that is encrypted with a hard coded key and IV (hint: Thycotic.ihawu.Base.FileHydrator class). As of Secret Server v10.4, the master key is obfuscated by being XORed against a hard-coded string, then encrypted with a hard coded key and stored in the encryption.config file.

Each entry is stored within the tbSecret table, and each item for that entry within the tbSecretItem table. tbSecret.key and tbSecret.IvMEK are the cipher text and IV respectively for the entry intermediate key, this is decrypted with the master key. tbSecretItem.ItemValue and tbSecretItem.IV are the cipher text and IV for the item itself (eg, the password), this is decrypted with the intermediate key. Invoke-SecretDecrypt can take these parameters and decrypt the item, you will also have to provide the encryption.config file from the Secret Server installation root.

## Compatibility

### < 10.4

This code has been tested on multiple Secret Server version V10.1 and V10.2 instances, running in the default configuration.

### == 10.4

SecretServer v10.4 is supported by this code. Specify the -NewFormat flag when running against the newer versions.

v10.4 implements a new format for the encryption.config file. The file now contains an encrypted blob that decrypts into a proprietary binary format. Some XOR logic is required to extract the length fields and key/value pairs from the decrypted blob. Take a look at the Get-MasterKeysv104 and Get-XORValue methods.

### > 10.4

SecretServer v10.5 and greater changed how keys and IVs are stored. Extraction can be done by using the steps detailed in [this issue](https://github.com/denandz/SecretServerSecretStealer/issues/5#issuecomment-666905276).

### DPAPI and HSM support

DPAPI is now supported by SecretServerSecretStealer. Naturally, you'll have to run the script on the SecretServer itself in order for decryption to work.  HSMs are not supported at this point.

If you would like to perform the secret decryption offline and the master key is protected with DPAPI, then you will need to extract the master key from the system first, then providing that in the Invoke-SecretDecrypt method. Something like:

```
$masterKeys = Get-MasterKeysv104 -path C:\inetpub\wwwroot\SecretServer\encryption.config
$masterkeys.IsEncryptedWithDPAPI # should return true
$decrypted = [Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($masterkeys.key256), $null, 'LocalMachine')
[Text.Encoding]::ASCII.GetString($decrypted)
```

The above will return the master AES256 key, which you can then use to decrypt items offline:

```
Invoke-SecretDecrypt -MasterKey <master key string from above> -Key <intermediate key cipher text> -IVMek <intermediate iv> -Item <item cipher text> -ItemIV <item iv>
```

For red-teamers trying to minimize their activities on a Secret Server, dumping the master keys (or copying out the `encryption.config` if DPAPI is not enabled), exfiltrating the database and performing the decryption offline may be a safer bet.

## Acknowledgements

* Adrian "I will reverse shit 8am on a Sunday in a café because that's the kinda cat I am" Hayes - (https://github.com/aj-code/)
* Dozer - 10.4 interop code and DPAPI support
* Whoever originally drew that hello kitty style baphomet...

## License

BSD License, see LICENSE file
