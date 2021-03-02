Banai is a single exeutable that runs Banaifile script file. Banaifile script is a Javascript ES5. This means you get all standard libraries from Javascript (ES5) plus objects and functions from banai executor. All the code in the example is a Javascript code written in Banaifile

# Running Banai
If you have a file called Banaifile in your folder, than running:
```
banai
```
Will execute the code in the Banaifile.

If you want to execute a specific banai file, use:
```
banai -f somefile.js
```

By default banai runs the main function inside the banai file. You can change that by naming a function in banaifile. 
For example. At `examples/Banaifile.js` we have a method called: `printOut` To call it directly from cli use:
```
banai -f examples/Banaifile.js printOut
```

You can see more example in banai at: `examples/Banaifile.js`


You can set secrets to the banai by the `-s ` flag, for example:
```
  banai -s examples/secret-file.json
```
For more information look at: [Working with secret configuration](#Secrets-configuration)


# Command reference of banai

All banai commands are organized into groups. In most cases the name of the function starts with the initions of the group follow by the function anme

## Archiving

### arZip
 Zip a folder
#### Synopsis
 arZip(zipFileName,FolderToZip)

#### Return
list of files that were zipped

---


### arUnzip
 Unzip a file to destination folder
#### Synopsis
 arUnzip(zipFileName,destinationFolder)
- __destinationFolder__ Destination folder is were the zip file will be extracted to. If this parameter is ommited will use current folder as destination

#### Return
list of files that were unzipped

---

## File system methods

These method are intended to ease the use of the standart file system API. Obviosly a shell has more options than this group of methods functions. However, these functions has some nice shortcuts or easier interface to run the basic fs functionality

### fsCreateDir
Create a folder and all its subfolders
#### Synopsis
fsCreateDir(dirName)

---

### fsRemoveDir
Remove a directory and all its content
#### Synopsis
fsRemoveDir(dirName)

---

### fsRead
Read a file from disk
#### Synopsis
fsRead(filePath)
#### result
Content of file as string or byte array

---

### fsRemove
Remove a file from disk
#### Synopsis
fsRemove(fileName)

---

### fsWrite
 Write text to file
#### Synopsis
fsWrite(filePath,content)
- __content__ Content of file can be a string or bytearray

---

### fsSplit
fsSplit splits path name to its components. 
#### Synopsis
fsSplit("/path/on/disk/file.ext")
#### result
object of returning all path parts
```javascript
type splitPathNameParts struct {
	"folder": "/path/on/disk"
	"file": "file.ext" 
	"title": "file"
	"ext": ".ext"
}

```

---

### fsList
fsList List all files and subfolders of root folder
#### Synopsis
fsList(rootFolder,searchMod)

- __rootFolder__ - The folder to search its content
- __searchMod__ - Optional, if empty all elements returned, if "f" only files are returned, if "d" only sub directory are returned

#### result
Array of names of elements

---

### fsAbs
fsAbs return the absolute path of a file or folder
#### Synopsis
fsAbs(pathName)

#### result
String of the absolute file name

---

### fsChdir
fsChdir Change current working dir
#### Synopsis
fsChdir(pathName)

---

### fsItemInfo
fsItemInfo return some information about a file or dir on the local fs. This method throws an exception if item not found

#### Synopsis
fsItemInfo("item name")

#### result
Return an object of 
```javascript
{
  isDir: false, //true if item is a folder
  isFile: false, //true if item is a file
  size: 123,  //Size of file
  lastModified: "2021-02-27T20:41:15.48840533+02:00" //Last modified time, as returned by of OS

}
```

If item was not found, an exception is thrown

---

## Hash calculators

### hashMd5File

calulate the hash of a file using md5

#### Synopsis
hashMd5File(fileName)

#### result
return md5 hex string of a file

---

### hashMd5Text

calulate the hash of a text using md5

#### Synopsis
hashMd5Text("Some string")

#### result

return md5 hex string of the source String

---

### hashMd5Buf

calulate the hash of a buffer using md5

#### Synopsis

hashMd5Buf(buffer)

#### result
return md5 hex string of the source buffer

---

### hashSha1File

calulate the hash of a file using SHA1

#### Synopsis
hashSha1File(fileName)

#### result
return SHA1 hex string of a file

---

### hashSha1Text

calulate the hash of a text using SHA1

#### Synopsis
hashSha1Text("Some string")

#### result

return SHA1 hex string of the source String

---

### hashSha1Buf

calulate the hash of a buffer using SHA1

#### Synopsis

hashSha1Buf(buffer)

#### result
return SHA1 hex string of the source String

---

### hash256File

calulate the hash of a file using SHA256

#### Synopsis
hash256File(fileName)

#### result
return SHA256 hex string of a file

---

### hashSha256Text

calulate the hash of a text using SHA256

#### Synopsis
hashSha256Text("Some string")

#### result

return SHA256 hex string of the source String

---

### hashSha256Buf

calulate the hash of a buffer using SHA256

#### Synopsis

hashSha256Buf(buffer)

#### result
return SHA256 hex string of the source buffer

---


## Http client
You can easly make http client request to a server. You can pass the url to the site, custome headers and cookies. If an error occurs an exception is thrown. 

You can pass options (not mandatory) to each request. Options field is:
``` javascript
{
  ignoreHttpsChecks: false, //Set to true (default) if you want to ignore checks on the https certificate. If set to false, client will fail on self signed certificate
  allowRedirect: false, //Follow redirect return from the server. Setting this field to false will not allow redirect (default is true).
  timeout: 10, // Send to complete the request. Set to zero (default) to never timeout
  herader: {"hdr1":["val1"]}, //Object containing array of strings to be set as the request header.
  cookies: [{}], //Array of cookie information
  contentType: "json", //A shortcut to set the request "Content-Type". Possible values: "json"
  Accept:"json" //A short cut to set the accept header. Possible values: "json","bin","text", default is json
}
```


If all is ok you get respons object with the following fields:
``` javascript
{
  "status": 200, // Http status code
  "rawBody": [64,13...], //If respond had a body. Than this is its raw representation as byte array
  "body" : any, //The parsed body
  "header": {"hdr1":"val1"}, //An object with field and value of the headers.
  "cookies": []{"Name": "value"} //cookie information
}
```

When aresponse had a body, Banai will try to parse the body. First as a string, then as a JSON. If its a json than body is the object of the json (or array). If it could not parse the respond as a json than body is the string, returned from the server. If the body of the respond was a byte array than body will hold a byte array (same as the rawBody)

These are the supported REST calls by Banai:

### httpGet 
Make a get request. No body is passed

#### Synopsis
httpGet(urlPath,opt)

---

### httpPost
make a post request. Passing the body as string or array of bytes
#### Synopsis
httpPost(urlPath,body,opt)

---

### httpPut
make a put request. Passing the body as string or array of bytes
#### Synopsis
httpPut(urlPath,body,opt)

---

### httpPatch
make a patch request. Passing the body as string or array of bytes
#### Synopsis
httpPatch(urlPath,body,opt)

---


### httpDelete
make a delete request. Passing the body as string or array of bytes
#### Synopsis
httpDelete(urlPath,body,opt)

I had decided to allow body to delete request, because the standart is not clear about this.

---

### httpOptions
make a options request.
#### Synopsis
httpOptions(urlPath,opt)

---

### httpHead
make a head request.
#### Synopsis
httpHead(urlPath,opt)

---


## Secrets
You initialize secrets by setting the -s/--secret flag to banai. To get the secrets at the Banai script use the following commands

### getTextSecret

Returns a text secret by id

#### Synopsis
getTextSecret("secret ID")

#### Result
The secret text as a string

---

### getSSHSecret

Returns ssh object

#### Synopsis
getTextSecret("secret ID")

#### Result
Text secret object
```javascript
{
  "user":"user of the ssh connection",
  "privateKeyFile": "Path to private key file",
  "passphrase": "passfrase to use with private key file"
}
```

---


### getUserPassSecret

Returns a user password secret

#### Synopsis
getTextSecret("secret ID")

#### Result
Text secret object
```javascript
{
  "user":"user of the ssh connection",
  "password": "the user password"
}
```

---




## Shell commands

### env
env is map that its keys are the name of the Environment-Variables and value of the Environment-Variable as string.
Both of these lines produce the same output:

``` javascript
println(env['DESKTOP_SESSION'])
println(env.DESKTOP_SESSION)
```

---

### println

Print text to screen and go down one line

#### Synopsis
println('test','text1',....)

---

### print

Print text to screen.

#### Synopsis
print('test','text1',....)

---


### pwd
pwd Return current working folder

---

### cd
cd Change current working dir

---


### rsh
Execute command on remote shell
#### Synopsis
rsh(sshConf,cmd)
- __sshConf__ = Object for configuring the remote shell
```javascript
{
  address: "www.remote-shell.com:22", //Host address and port of remote server that runs ssh server
  user: "user", //The user to use to connect to the remote server
  password: "password", //If using user name and password, this would be the password to login to the remote server
  privateKeyFile: "~/.ssh/pc.pem", //Name of private key file
  passphrase: "some passphrase",// If the private key is protected by a passphrase than this field must be set
  secretId: "Banai managed Secret id value"
}
```
- __cmd__ = The command to run on the remote server

#### Result
Return an object with the execution result
```javascript
{
  Code: 0,   //Zero if all is ok. If stderr has info than code is 1
  Out: "Some output if any", //The stdout content from the remote shell
  Err: "Some text if any"   //The stderr content from the remote shell
}
```

---

### sh
Execute a shell command. It uses /bin/bash as default.
#### Synopsis
sh(cmd,opt)

- _cmd_ - Text of the command line to run
- _opt_ - Object with this fields:
```javascript
{
   "shell": "/bin/bash",  //Alternative to /bin/bash
   "in": "single line", //A single line to pass to stdin, if the command needs one
   "ins": ["Line 1","Line 2"], // Multi lines to pass to stdin. Line per element in array
   "timeout": 10 // Timeout in seconds. After this time the command execution is terminated
   "secretId": "Banai managed secret ID" //
}
```

#### Result
The command returns an object with these fields:
```javascript
{
   "code" : 0, //The exit code of the shell script
   "out" : "output text", //text from stdout of the command, if any.
   "err" : "stderr text" //text from stderr of the command, if any.
}
```

---

### shScript
Execute a shell script. It uses /bin/bash as default.
#### Synopsis
shScript(scriptFileName,opt)

- _cmd_ - Text of the command line to run
- _opt_ - Object with this fields:
```javascript
{
   "shell": "/bin/bash",  //Alternative to /bin/bash
   "in": "single line", //A single line to pass to stdin, if the command needs one
   "ins": ["Line 1","Line 2"], // Multi lines to pass to stdin. Line per element in array
   "timeout": 10 // Timeout in seconds. After this time the command execution is terminated
   "secretId": "Banai managed secret ID" //
}
```

#### Result
The command returns an object with these fields:
```javascript
{
   "code" : 0, //The exit code of the shell script
   "out" : "output text", //text from stdout of the command, if any.
   "err" : "stderr text" //text from stderr of the command, if any.
}
```

---

### shUpload
Upload file to a remote machine via ssh
#### Synopsis
shUpload(sshConf,localFile,remoteFile)
- __sshConf__ = Object for configuring the remote shell
```javascript
{
  address: "www.remote-shell.com:22", //Host address and port of remote server that runs ssh server
  user: "user", //The user to use to connect to the remote server
  password: "password", //If using user name and password, this would be the password to login to the remote server
  privateKeyFile: "~/.ssh/pc.pem", //Name of private key file
  passphrase: "some passphrase"// If the private key is protected by a passphrase than this field must be set
}
```

- __localFile__ - Local file path
- __remoteFile__ - Remote file path

If all is ok the function returns. On error execution stops

---

### shDownload
Download file from remote machine via ssh
#### Synopsis
shDownload(sshConf,remoteFile,localFile)
- __sshConf__ = Object for configuring the remote shell
```javascript
{
  address: "www.remote-shell.com:22", //Host address and port of remote server that runs ssh server
  user: "user", //The user to use to connect to the remote server
  password: "password", //If using user name and password, this would be the password to login to the remote server
  privateKeyFile: "~/.ssh/pc.pem", //Name of private key file
  passphrase: "some passphrase"// If the private key is protected by a passphrase than this field must be set
}
```
- __remoteFile__ - Remote file path
- __localFile__ - Local file path
If all is ok the function returns. On error execution stops


---

## function main()
The entry point method, if no other method is called from the shell.





# Secrets configuration

You can load secrets into Banai. If you have a secret set you can refer to it by its id. The relevant command will use that secret to call their function. For example. you can set a user/password secret and when calling rsh pass the secret id. Banai will initiatl ssh connection using the information in the secret.

Banai has several types of secrets:

- Text - A simple text.
- SSH - An ssh information including: user name, private key content and passphrase if any exists.
- User/Pass - The classic username password pairs

A secret configuration file has the following format:
``` javascript
{
  "secrets":[
    {
      "id" : "a secret is",
      "type" : "type of secert. one of: text,ssh,userpass",
      ...
    },
    {
      "id" : "Another secret",
      "type" : "type of secert. one of: text,ssh,userpass",
      ...
    }
  ]

}

```

## Text secret config object:
```javascript
{
  "id": "some id",
  "type": "text",
  "text": "a secret text"
}
```

## ssh secret config object:
```javascript
{
  "id": "some id",
  "type": "ssh",
  "user": "user name",
  "privateKey":"base64 of private key content",
  "passphrase":"The passphrase for the privateKey, if it is protected by one"
}
```

## user/password config object:
```javascript
{
  "id": "some id",
  "type": "ssh",
  "user": "user name",
  "password":"password",
  
}
```






### Command
general description

#### Synopsis
how to run

#### Result
object of returning all path parts
```javascript

```

---
