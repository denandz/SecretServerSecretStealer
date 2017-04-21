# SecretServerSecretStealer

<img src="https://raw.githubusercontent.com/denandz/SecretServerSecretStealer/master/images/logo.png" width="210px" height="206px">

SecretServerSecretStealer is a powershell script that allows for the decryption of passwords (and other items) stored within a Thycotic Secret Server installation. Two methods are exposed, Invoke-SecretDecrypt and Invoke-SecretStealer. 

Invoke-SecretDecrypt requires you to manually pass the various data needed to decrypt a single secret (see Decryption). Invoke-SecretStealer is designed to be run on a Thycotic Secret Server machine itself, and takes only the web root as a parameter. The SecretStealer will decrypt the database configuration and connect to the applications db. All relevant information is extracted, and all secrets decrypted. 

## Execution
Invoke-SecretStealer should be executed on the Secret Server itself, for example:

```
Invoke-SecretStealer -WebRoot C:\inetpub\wwwroot\SecretServer
```

<img src="https://raw.githubusercontent.com/denandz/SecretServerSecretStealer/master/images/invoke-secretstealer.png">

Invoke-SecretDecrypt can be excecuted to decrypt a specific item. You need to retrieve from the db the following fields: tbSecret.key, tbSecret.IvMEK, tbSecretItem.IV and tbSecretItem.ItemValue. Be sure to corellate the SecretID between these entries, as the intermediate keys are unique to a specific SecretID. The following SQL may be used to dump all of the relevant information, along with some other auxilliary data:

```
select s.SecretName, f.SecretFieldName, s.[Key], s.IvMEK, i.ItemValue, i.IV from tbSecretItem as i JOIN tbSecret as s ON (s.SecretID = i.SecretID) JOIN tbSecretField as f on (i.SecretFieldID = f.SecretFieldID)
```

After retrieving the above, you can run Invoke-SecretDecrypt

```
Invoke-SecretDecrypt -Item 9993c5097491ba2b42a10b9a9b7a6ab7239b107337c348086eeb5f5b29c76f33 -ItemIV CF4C2D4F7FA432D64D9712212A06EEA9 -IVMek 6080667306DA295A75E22667E9AD0376 -Key 5C195A500A3BF87C29163A52AC4EA2CFF6C5B69407B6F91A7C7B100B6D20121AAFD052C11B13D542EA2F42137258C2EF -EncryptionConfig C:\whatever\encryption.config
```

## Decryption

The Thycotic Secret Server essentially works on the principle of 'more crypto, more better'. Every entry has multiple items, such as a password, name, url, etcetera. Each of these items are encrypted with an intermediate key that is specific to that entry. That intermediate key is encrypted by a master key, which is unique to each installation and stored in the encryption.config file. The encryption.config file itself is a binary serialized object that is encrypted with a hard coded key and IV (hint: Thycotic.ihawu.Base.FileHydrator class). 

Each entry is stored within the tbSecret table, and each item for that entry within the tbSecretItem table. tbSecret.key and tbSecret.IvMEK are the cipher text and IV respectively for the entry intermediate key, this is decrypted with the master key. tbSecretItem.ItemValue and tbSecretItem.IV are the cipher text and IV for the item itself (eg, the password), this is decrypted with the intermediate key. Invoke-SecretDecrypt can take these parameters and decrypt the item, you will also have to provide the encryption.config file from the Secret Server installation root.

## Compatibility
This code has been tested on multiple Secret Server version V10.1 and V10.2 instances, running in the default configuration. Secret Server does support HSM and DPAPI, however neither of these are accounted for in this script at this time. Additionally, these features are not configured by default. 

If you encounter an instance with DPAPI enabled, then some additional reversing will be required in order to figure out when to call machine key unprotect. (IsEncryptedWithDPAPI and Thycotic.AppCore.DPAPIEncryptor would be a good start)

If your target is using an HSM then you're on your own, please let me know how it turns out!

## Acknowledgements
* Adrian "I will reverse shit 8am on a Sunday in a café because that's the kinda cat I am" Hayes - (https://github.com/aj-code/)
* Whoever originally drew that hello kitty style baphomet... 

## License
BSD License, see LICENSE file
