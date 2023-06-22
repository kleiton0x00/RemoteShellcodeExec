# Inject-http BOF
A custom `inject` function of Cobalt Strike, which injects the shellcode in a process by retrieving the shellcode from a remote HTTP server.

## Usage  

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
