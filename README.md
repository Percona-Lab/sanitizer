# Logs Sanitizer

This is a set of tools to sanitize log files and encrypt them to safelly send them to support.  
The tools are:

### Sanitizer

Replaces all the queries in a file by their fingerprints and also replaces hostnames by the text `<hostname>`.
It reads text from the standard input and the output is sent to the standard output to make it able to use in Linux pipes.  

#### Flags
|Flag|Description|
|-----|-----|
|--help|Show context-sensitive help (also try --help-long and --help-man).|
|--input-file=INPUT-FILE|Input file. If not specified, the input will be Stdin.|
|--outout-file=OUTOUT-FILE|Output file. If not specified, the input will be Stdout.|
|--no-sanitize-hostnames|Do not sanitize host names.|
|--no-sanitize-queries|Do not replace queries by their fingerprints|
  
#### Usage
```
sanitize < input-file > output-file
```

### Collector
  
This program collects the output of `pt-stalk`, sanitizes the output, compress the files into a `.tar.gz` and encrypts the tar file to be safelly sent to support.  
By default, it runs: 
````
pt-stalk --no-stalk --iterations=2 --sleep=30 --host=$mysql-host --dest=$data-dir --port=$mysql-port --user=$mysql-user --password=$mysql-pass
```
Where `$variable` is being replaced by the corresponding command line parameter, ie, `$mysql-user` is going to be replaced by the value of the `--mysql-user` parameter.

#### Flags
  
|Flag|Description|
|-----|-----|
|--help|Show context-sensitive help (also try --help-long and --help-man)|

|--bin-dir|Directory having the Percona Toolkit binaries (if they are not in PATH)|
|--data-dir|Directory to store the output. By default a directory name with the form ${HOME}/data_collection_YYYY-MM-DD_HH_mm_ss wil be created. The directory may already contain files that will be included into the .tar.gz file|
|--config-file|MySQL config file. Default=${HOME}/.my.cnf|
|--mysql-host|MySQL host|
|--mysql-port|MySQL port|
|--mysql-user|MySQL user name|
|--mysql-pass|MySQL password|
|--ask-pass|Ask MySQL password|
|--no-default-commands|Do not run the default commands (pt-stalk)|
|--no-sanitize-hostnames|Do not sanitize host names|
|--no-sanitize-queries|Do not replace queries by their fingerprints|
|--extra-cmd|Also run this command as part of the data collection. This parameter can be used more than once|
|--encrypt-password|Encrypt the output file using this password. If ommited, the file won't be encrypted.|

##### Usage
1. Collects the data and encrypt the output using a password  
```
collect --encrypt-password=a-secure-password
```
2. Collect if Percona Toolkit is not in the PATH
```
collect --bin-dir=path/to/percona/toolkit --encrypt-password=a-secure-password
```
3. Do not run `pt-stalk`, just collect, compress and encrypt existing files  
```
collect --no-default-commands --data-dir=/path/to/existing/files --encrypt-password=a-secure-password
```

### Encrypt/Decrypt 

This program can encrypt/decrypt a file using AES algorithm.  
It mainly purpose is to decrypt the file encrypted by the collector.

##### Usage
1. Decrypt a file
```
encryptor decrypt <encrypted file> <unencrypted file>
```
2. Encrypt a file
```
encryptor encrypt <unencrypted file> <encrypted file>
```

