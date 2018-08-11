package main

import (
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

const (
	//REVISIT_VERSION - server version or node, not yet used
	REVISIT_VERSION = "0.5"

	//common constants
	CODE_LENGTH     = 64 //length code
	PASSWORD_LENGTH = 14
	FILE_PROFILES   = "profiles.list"
	FILE_OPTIONS    = "options.cfg"
	FILE_COUNTERS   = "counters.json"
	FILE_VNCLIST    = "vnc.list"
	LOG_NAME        = "log.txt"
	MAX_LEN_ID_LOG  = 6
	MAX_LEN_ID_NODE = 8
	LEN_SALT        = 16

	//Waiting constants
	WAIT_COUNT         = 30
	WAIT_IDLE          = 500
	WAIT_AFTER_CONNECT = 250
	WAIT_HELPER_CYCLE  = 5
	WAIT_PING          = 10
	WAIT_IDLE_AGENT    = 2

	//types of log messages
	MESS_ERROR  = 1
	MESS_INFO   = 2
	MESS_DETAIL = 3
	MESS_FULL   = 4

	//types of messages
	TMESS_DEAUTH          = 0  //deauthentication ()
	TMESS_VERSION         = 1  //version request
	TMESS_AUTH            = 2  //Authentication (pid generation)
	TMESS_LOGIN           = 3  //entrance to the profile
	TMESS_NOTIFICATION    = 4  //message customer
	TMESS_REQUEST         = 5  //connection request
	TMESS_CONNECT         = 6  //we request connection from the client
	TMESS_DISCONNECT      = 7  //we inform about disconnection to the client
	TMESS_REG             = 8  //profile registration
	TMESS_CONTACT         = 9  //creation, editing, deletion
	TMESS_CONTACTS        = 10 //contact list request
	TMESS_LOGOUT          = 11 //exit from the profile
	TMESS_CONNECT_CONTACT = 12 //request to connect to a contact from the profile
	TMESS_STATUSES        = 13 //request all statuses
	TMESS_STATUS          = 14 //status request
	TMESS_INFO_CONTACT    = 15 //requesting customer information
	TMESS_INFO_ANSWER     = 16 //response to information request
	TMESS_MANAGE          = 17 //request for management (reboot, update, reinstall)
	TMESS_PING            = 18 //checking the connection status
	TMESS_CONTACT_REVERSE = 19 //adding yourself to someone else's profile

	TMESS_AGENT_DEAUTH      = 0
	TMESS_AGENT_AUTH        = 1
	TMESS_AGENT_ANSWER      = 2
	TMESS_AGENT_ADD_CODE    = 3
	TMESS_AGENT_DEL_CODE    = 4
	TMESS_AGENT_NEW_CONNECT = 5
	TMESS_AGENT_DEL_CONNECT = 6
	TMESS_AGENT_ADD_BYTES   = 7

	REGULAR = 0
	MASTER  = 1
	NODE    = 2
)

var (

	//default options
	options = Options{
		MainServerPort: "65471",
		DataServerPort: "65475",
		HttpServerPort: "8090",
		SizeBuff:       16000,
		AdminLogin:     "admin",
		AdminPass:      "admin",
		Mode:           REGULAR,
		FDebug:         true,
		MasterServer:   "data.rvisit.net",
		MasterPort:     "65470",
		MasterPassword: "master",
	}

	//consider any useless information or not
	counterData struct {
		currentPos time.Time

		CounterBytes       [24]uint64
		CounterConnections [24]uint64
		CounterClients     [24]uint64

		CounterDayWeekBytes       [7]uint64
		CounterDayWeekConnections [7]uint64
		CounterDayWeekClients     [7]uint64

		CounterDayBytes       [31]uint64
		CounterDayConnections [31]uint64
		CounterDayClients     [31]uint64

		CounterDayYearBytes       [365]uint64
		CounterDayYearConnections [365]uint64
		CounterDayYearClients     [365]uint64

		CounterMonthBytes       [12]uint64
		CounterMonthConnections [12]uint64
		CounterMonthClients     [12]uint64

		mutex sync.Mutex
	}

	//admin menu
	menuAdmin = []itemMenu{
		{"Logs", "/admin/logs"},
		{"Settings", "/admin/options"},
		{"Resources", "/admin/resources"},
		{"Statistics", "/admin/statistics"},
		{"reVisit", "/resource/reVisit.exe"}}

	//menu web interface profile
	menuProfile = []itemMenu{
		{"Profile", "/profile/my"},
		{"reVisit", "/resource/reVisit.exe"}}

	//maximum log level
	typeLog = MESS_FULL

	//log file
	logFile *os.File

	//map of connected clients
	clients sync.Map

	//channel map for data transmission
	channels sync.Map

	//card reader
	profiles sync.Map

	//data processing agents
	nodes sync.Map

	//socket to master
	master *net.Conn

	//text decryption of messages for logs
	messLogText = []string{
		"BLANK",
		"ERROR",
		"INFO",
		"DETAIL",
		"FULL"}

	//functions for processing messages
	processing = []ProcessingMessage{
		{TMESS_DEAUTH, nil},
		{TMESS_VERSION, processVersion},
		{TMESS_AUTH, processAuth},
		{TMESS_LOGIN, processLogin},
		{TMESS_NOTIFICATION, processNotification},
		{TMESS_REQUEST, processConnect},
		{TMESS_CONNECT, nil},
		{TMESS_DISCONNECT, processDisconnect},
		{TMESS_REG, processReg},
		{TMESS_CONTACT, processContact},
		{TMESS_CONTACTS, processContacts},
		{TMESS_LOGOUT, processLogout},
		{TMESS_CONNECT_CONTACT, processConnectContact},
		{TMESS_STATUSES, processStatuses},
		{TMESS_STATUS, processStatus},
		{TMESS_INFO_CONTACT, processInfoContact},
		{TMESS_INFO_ANSWER, processInfoAnswer},
		{TMESS_MANAGE, processManage},
		{TMESS_PING, processPing},
		{TMESS_CONTACT_REVERSE, processContactReverse}}

	processingAgent = []ProcessingAgent{
		{TMESS_AGENT_DEAUTH, nil},
		{TMESS_AGENT_AUTH, processAgentAuth},
		{TMESS_AGENT_ANSWER, processAgentAnswer},
		{TMESS_AGENT_ADD_CODE, processAgentAddCode},
		{TMESS_AGENT_DEL_CODE, processAgentDelCode},
		{TMESS_AGENT_NEW_CONNECT, processAgentNewConnect},
		{TMESS_AGENT_DEL_CONNECT, processAgentDelConnect},
		{TMESS_AGENT_ADD_BYTES, processAgentAddBytes}}

	//functions for processing web api
	processingWeb = []ProcessingWeb{
		{"defaultvnc", processApiDefaultVnc},
		{"listvnc", processApiListVnc},
		{"getlog", processApiGetLog},
		{"clearlog", processApiClearLog},
		{"profile_save", processApiProfileSave},
		{"profile_get", processApiProfileGet},
		{"save_options", processApiSaveOptions},
		{"options_save", processApiOptionsSave},
		{"reload", processApiReload},
		{"options_get", processApiOptionsGet}}

	//list of available vnc clients and selected by default
	defaultVnc = 0
	arrayVnc   []VNC
)

//double pointer
type dConn struct {
	pointer [2]*net.Conn
	flag    [2]bool
	node    [2]*Node
	mutex   sync.Mutex
}

//information about the node
type Node struct {
	Id   string
	Name string
	Ip   string
	Conn *net.Conn
}

//handler for web request
type ProcessingWeb struct {
	Make       string
	Processing func(w http.ResponseWriter, r *http.Request)
}

//handler for agent requests
type ProcessingAgent struct {
	TMessage   int
	Processing func(message Message, conn *net.Conn, curNode *Node, id string)
}

//message handler
type ProcessingMessage struct {
	TMessage   int
	Processing func(message Message, conn *net.Conn, curClient *Client, id string)
}

//type for message
type Message struct {
	TMessage int
	Messages []string
}

//saved options
type Options struct {
	//smtp server settings
	ServerSMTP string
	PortSMTP   string
	LoginSMTP  string
	PassSMTP   string

	//server requisites
	MainServerPort string

	//details of the server
	DataServerPort string

	//web server details
	HttpServerPort string

	//buffer size for operations with sockets
	SizeBuff int

	//account for admin panel
	AdminLogin string
	AdminPass  string

	//server instance operation mode
	Mode int

	//master server if you need it
	MasterServer   string
	MasterPort     string
	MasterPassword string

	//obviously the flag for debugging
	FDebug bool
}

//information about the company and the main commands for managing it
type VNC struct {
	FileServer string
	FileClient string

	//this command is used to start under admin rights (usually this is the creation of a service)
	CmdStartServer   string
	CmdStopServer    string
	CmdInstallServer string
	CmdRemoveServer  string
	CmdConfigServer  string
	CmdManageServer  string

	//this room is used for start without admin rights
	CmdStartServerUser   string
	CmdStopServerUser    string
	CmdInstallServerUser string
	CmdRemoveServerUser  string
	CmdConfigServerUser  string
	CmdManageServerUser  string

	//for vnc client
	CmdStartClient   string
	CmdStopClient    string
	CmdInstallClient string
	CmdRemoveClient  string
	CmdConfigClient  string
	CmdManageClient  string

	PortServerVNC string
	Link          string
	Name          string
	Version       string
	Description   string
}

//menu for the web
type itemMenu struct {
	Capt string
	Link string
}

//customer type
type Client struct {
	Serial  string
	Pid     string
	Pass    string
	Version string
	Salt    string //for password
	Profile *Profile

	Conn *net.Conn
	Code string //for connection

	profiles sync.Map //profiles that contain this client in contacts (we use to send them information about their status)
}

//type for profile
type Profile struct {
	Email string
	Pass  string

	Contacts *Contact
	mutex    sync.Mutex

	clients sync.Map //clients who are authorized in this profile (we use to send them information about the status or changes of contacts)

	//any information
	Capt string
	Tel  string
	Logo string
}

//type for contact
type Contact struct {
	Id      int
	Caption string
	Type    string //account - contact, fold - folder
	Pid     string
	Digest  string //but digest here
	Salt    string

	Inner *Contact
	Next  *Contact
}
