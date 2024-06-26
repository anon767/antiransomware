# Anti Ransomware Tool

Ransomware malware is a software program which scans for sensitive files and encrypts them. They usually then try to convince the user to pay a ransom to get the decryption key.
There is some research work on how to detect ransomware using file-based entropy. Files with higher entropy are likely being encrypted [1,2]. 
There are false positives where we may detect compressed files as encrypted and there are false negatives where malware might use structural encryption or only partially encrypt files [3].


## Antiransomware

This project offers a new way to detect ransomware. We inject a DLL into user processes to look for file modification operations. If the entropy of the written buffer is above 7.5 bits per Byte on average, it is likely  being replaced by an encrypted version. Except, when the entropy was already high in the first place. This could be potentially improved by also hooking for newly created files and checking file type, size and access patterns of the injected process.

## How to use?

Build the injector and the anticrypter library as x64. Place them in the same folder and run the injector as Admin. A small system tray icon appears.
Now every process will be monitored for suspicious file access. If something has been detected, the write is being blocked.

Injector logs are written to:
```
%temp%/injector_log.txt
```
Anticrypter logs are written to:
```
%temp%/write_intercept.txt 
```


## System Integration
You can automatically inject the anticrypter dll into any starting process (that depends on user32.dll).
Adjust this and save it as install.reg.
```
[HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows]
"AppInit_DLLs"="PathToDLL.dll"
"LoadAppInit_DLLs"=dword:00000001
"RequireSignedAppInit_DLLs"=dword:00000000
```

## Disclaimer
This is only for educational purposes.



[1] https://ieeexplore.ieee.org/abstract/document/8772046

[2] https://content.iospress.com/articles/journal-of-computer-security/jcs191346

[3] https://link.springer.com/chapter/10.1007/978-3-030-30143-9_11
