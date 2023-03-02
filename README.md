# RemoteShellcodeExec
A simple PoC of executing shellcode from a remote-hosted bin file using Winhttp. This is demo of the relevant blog post: [Shellcodes are dead, long live fileless shellcodes](https://kleiton0x00.github.io/posts/Shellcodes-are-dead-long-live-fileless-shellcodes/).

## TL;DR  
- Executing the shellcode from a remote-hosted server, will make the executable file itself drastically reduce it's entropy.  
- Implemented a simple heap encryption, to avoid the shellcode being visible  
- Profit (0/26 detections)

## Demo
https://user-images.githubusercontent.com/37262788/222574293-9dc8a0e5-0fe1-48bf-96c9-b7dc70a9898b.mp4

## Credits  
https://decoded.avast.io/threatintel/decoding-cobalt-strike-understanding-payloads/  
https://twitter.com/teamcymru_S2/status/1604091964386705409  
https://www.huntress.com/blog/hackers-no-hashing-randomizing-api-hashes-to-evade-cobalt-strike-shellcode-detection
