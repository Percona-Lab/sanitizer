# pt-secure-data
Collect, sanitize, pack and encrypt data. By default, this program will collect the output of:

- `pt-stalk --no-stalk --iterations=2 --sleep=30 --host=$mysql-host --dest=$temp-dir --port=$mysql-port --user=$mysql-user --password=$mysql-pass`
- `pt-summary`
- `pt-mysql-summary --host=$mysql-host --port=$mysql-port --user=$mysql-user --password=$mysql-pass`



Usage:  
```
pt-secure-data [<flags>] <command> [<args> ...]
```


### Global flags
|Flag|Description|
|-----|-----|
|--help|Show context-sensitive help (also try --help-long and --help-man).|
|--debug|Enable debug log level.|

### **Commands**
#### **Help command**
Show help

#### **Collect command**
Collect, sanitize, pack and encrypt data from pt-tools.
Usage:
```
sanitizer collect <flags>
```

|Flag|Description|
|-----|-----|
|--bin-dir|Directory having the Percona Toolkit binaries (if they are not in PATH).|
|--temp-dir|Temporary directory used for the data collection. Default: ${HOME}/data_collection\_{timestamp}| 
|--include-dir|Include this dir into the sanitized tar file|
|--config-file|Path to the config file. Default: `~/.my.cnf`|
|--mysql-host|MySQL host. Default: `127.0.0.1`|
|--mysql-port|MySQL port. Default: `3306`|
|--mysql-user|MySQL user name.|
|--mysql-password|MySQL password.|
|--ask-mysql-pass|Ask MySQL password.|
|--extra-cmd|Also run this command as part of the data collection. This parameter can be used more than once.|
|--encrypt-password|Encrypt the output file using this password.<br>If ommited, it will be asked in the command line.|
|--no-collect|Do not collect data|
|--no-sanitize|Do not sanitize data|
|--no-encrypt|Do not encrypt the output file.|
|--no-sanitize-hostnames|Do not sanitize host names.|
|--no-sanitize-queries|Do not replace queries by their fingerprints.|
|--no-remove-temp-files|Do not remove temporary files.|

#### **Decrypt command**
Decrypt an encrypted file. The password will be requested from the terminal.  
Usage: 
```
sanitizer decrypt <input file> <output file>
```

#### **Encrypt command**
Encrypt a file. The password will be requested from the terminal.  
Usage: 
```
sanitizer encrypt <input file> <output file>
```  

#### **Sanitize command**
Replace queries in a file by their fingerprints and obfuscate hostnames.  
Usage:
```
sanitizer sanitize [flags]
```
  
|Flag|Description|
|-----|-----|
|--input-file| Input file. If not specified, the input will be Stdin.|
|--output-file|Output file. If not specified, the input will be Stdout.|
|--no-sanitize-hostnames|Do not sanitize host names.|
|--no-sanitize-queries|Do not replace queries by their fingerprints.|

