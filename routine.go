package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"strings"
	"time"
)

func helperThread() {
	logAdd(MESS_INFO, "helperThread started")
	for true {
		saveProfiles()
		swiftCounter()

		time.Sleep(time.Second * WAIT_HELPER_CYCLE)
	}
	logAdd(MESS_INFO, "helperThread finished")
}

func getPid(serial string) string {

	var a uint64 = 1
	for _, f := range serial {
		a = a * uint64(f)
	}

	//todo fakir was drunk, but so far and so come down
	b := a % 999
	if b == 0 {
		b = 1
	}
	for b < 100 {
		b = b * 10
	}
	c := (a / 999) % 999
	if c == 0 {
		c = 1
	}
	for c < 100 {
		c = c * 10
	}
	d := ((a / 999) / 999) % 999
	if d == 0 {
		d = 1
	}
	for d < 100 {
		d = d * 10
	}
	e := (((a / 999) / 999) / 999) % 999
	if e == 0 {
		e = 1
	}
	for e < 100 {
		e = e * 10
	}

	return fmt.Sprintf("%d:%d:%d:%d", b, c, d, e)
}

func logAdd(TMessage int, Messages string) {
	if options.FDebug && typeLog >= TMessage {

		if logFile == nil {
			logFile, _ = os.Create(LOG_NAME)
		}

		//todo probably worth removing, but so far prevents the ping in the logs
		if strings.Contains(Messages, "buff (31): {\"TMessage\":18,\"Messages\":null}") || strings.Contains(Messages, "{18 []}") {
			return
		}

		logFile.Write([]byte(fmt.Sprint(time.Now().Format("02 Jan 2006 15:04:05.000000")) + "\t" + messLogText[TMessage] + ":\t" + Messages + "\n"))

		fmt.Println(fmt.Sprint(time.Now().Format("02 Jan 2006 15:04:05.000000")) + "\t" + messLogText[TMessage] + ":\t" + Messages)
	}

}

func createMessage(TMessage int, Messages ...string) Message {
	var mes Message
	mes.TMessage = TMessage
	mes.Messages = Messages
	return mes
}

func randomString(l int) string {
	var result bytes.Buffer
	var temp string
	for i := 0; i < l; {
		if string(randInt(65, 90)) != temp {
			temp = string(randInt(65, 90))
			result.WriteString(temp)
			i++
		}
	}
	return result.String()
}

func randInt(min int, max int) int {
	rand.Seed(time.Now().UTC().UnixNano())
	return min + rand.Intn(max-min)
}

func sendMessage(conn *net.Conn, TMessage int, Messages ...string) bool {
	if conn == nil {
		logAdd(MESS_ERROR, "no socket to send")
		return false
	}

	var mes Message
	mes.TMessage = TMessage
	mes.Messages = Messages

	out, err := json.Marshal(mes)
	if err == nil && conn != nil {
		_, err = (*conn).Write(out)
		if err == nil {
			return true
		}
	}
	return false
}

func getSHA256(str string) string {

	s := sha256.Sum256([]byte(str))
	var r string

	for _, x := range s {
		r = r + fmt.Sprintf("%02x", x)
	}

	return r
}

func delContact(first *Contact, id int) *Contact {
	if first == nil {
		return first
	}

	for first != nil && first.Id == id {
		first = first.Next
	}

	res := first

	for first != nil {
		for first.Next != nil && first.Next.Id == id {
			first.Next = first.Next.Next
		}

		if first.Inner != nil {
			first.Inner = delContact(first.Inner, id)
		}

		first = first.Next
	}

	return res
}

func getContact(first *Contact, id int) *Contact {

	for first != nil {
		if first.Id == id {
			return first
		}

		if first.Inner != nil {
			inner := getContact(first.Inner, id)
			if inner != nil {
				return inner
			}
		}

		first = first.Next
	}

	return nil
}

func getContactByPid(first *Contact, pid string) *Contact {

	for first != nil {
		if cleanPid(first.Pid) == pid {
			return first
		}

		if first.Inner != nil {
			inner := getContactByPid(first.Inner, pid)
			if inner != nil {
				return inner
			}
		}

		first = first.Next
	}

	return nil
}

func getNewId(first *Contact) int {
	if first == nil {
		return 1
	}

	r := 1

	for first != nil {

		if first.Id >= r {
			r = first.Id + 1
		}

		if first.Inner != nil {
			t := getNewId(first.Inner)
			if t >= r {
				r = t + 1
			}
		}

		first = first.Next
	}

	return r
}

func saveProfiles() {
	var list []*Profile

	profiles.Range(func(key interface{}, value interface{}) bool {
		profile := value.(*Profile)
		list = append(list, profile)
		return true
	})

	b, err := json.Marshal(list)
	if err == nil {
		f, err := os.Create(FILE_PROFILES + ".tmp")
		if err == nil {
			n, err := f.Write(b)
			if n == len(b) && err == nil {
				f.Close()

				os.Remove(FILE_PROFILES)
				os.Rename(FILE_PROFILES+".tmp", FILE_PROFILES)
			} else {
				f.Close()
				logAdd(MESS_ERROR, "Failed to save profiles: "+fmt.Sprint(err))
			}
		} else {
			logAdd(MESS_ERROR, "Failed to save profiles: "+fmt.Sprint(err))
		}
	} else {
		logAdd(MESS_ERROR, "Failed to save profiles: "+fmt.Sprint(err))
	}
}

func loadProfiles() {
	var list []Profile

	f, err := os.Open(FILE_PROFILES)
	defer f.Close()
	if err == nil {
		b, err := ioutil.ReadAll(f)
		if err == nil {
			err = json.Unmarshal(b, &list)
			if err == nil {
				for i := 0; i < len(list); i++ {
					profiles.Store(list[i].Email, &list[i])
				}
			} else {
				logAdd(MESS_ERROR, "Can not load profiles: "+fmt.Sprint(err))
			}
		} else {
			logAdd(MESS_ERROR, "Can not load profiles: "+fmt.Sprint(err))
		}
	} else {
		logAdd(MESS_ERROR, "Can not load profiles: "+fmt.Sprint(err))
	}
}

func saveOptions() {
	b, err := json.Marshal(options)
	if err == nil {
		f, err := os.Create(FILE_OPTIONS + ".tmp")
		if err == nil {
			n, err := f.Write(b)
			if n == len(b) && err == nil {
				f.Close()

				os.Remove(FILE_OPTIONS)
				os.Rename(FILE_OPTIONS+".tmp", FILE_OPTIONS)
			} else {
				f.Close()
				logAdd(MESS_ERROR, "Failed to save settings: "+fmt.Sprint(err))
			}
		} else {
			logAdd(MESS_ERROR, "Failed to save settings: "+fmt.Sprint(err))
		}
	} else {
		logAdd(MESS_ERROR, "Failed to save settings: "+fmt.Sprint(err))
	}
}

func loadOptions() {
	f, err := os.Open(FILE_OPTIONS)
	defer f.Close()
	if err == nil {
		b, err := ioutil.ReadAll(f)
		if err == nil {
			err = json.Unmarshal(b, &options)
			if err != nil {
				logAdd(MESS_ERROR, "Unable to load settings: "+fmt.Sprint(err))
			}
		} else {
			logAdd(MESS_ERROR, "Unable to load settings: "+fmt.Sprint(err))
		}
	} else {
		logAdd(MESS_ERROR, "Unable to load settings: "+fmt.Sprint(err))
	}
}

//func saveVNCList(){
//
//	b, err := json.Marshal(array_vnc)
//	if err == nil {
//		f, err := os.Create(FILE_VNCLIST + ".tmp")
//		if err == nil {
//			n, err := f.Write(b)
//			if n == len(b) && err == nil {
//				f.Close()
//
//				os.Remove(FILE_VNCLIST)
//				os.Rename(FILE_VNCLIST + ".tmp", FILE_VNCLIST)
//			} else {
//				f.Close()
//				logAdd(MESS_ERROR, "Failed to save VNC list: " + fmt.Sprint(err))
//			}
//		} else {
//			logAdd(MESS_ERROR, "Failed to save VNC list: "+fmt.Sprint(err))
//		}
//	} else {
//		logAdd(MESS_ERROR, "Failed to save VNC list: " + fmt.Sprint(err))
//	}
//}

func loadVNCList() {

	f, err := os.Open(FILE_VNCLIST)
	defer f.Close()
	if err == nil {
		b, err := ioutil.ReadAll(f)
		if err == nil {
			err = json.Unmarshal(b, &arrayVnc)
			if err == nil {
				defaultVnc = 0
			} else {
				logAdd(MESS_ERROR, "It was not possible to load the VNC list: "+fmt.Sprint(err))
			}
		} else {
			logAdd(MESS_ERROR, "It was not possible to load the VNC list: "+fmt.Sprint(err))
		}
	} else {
		logAdd(MESS_ERROR, "It was not possible to load the VNC list: "+fmt.Sprint(err))
	}
}

//go over profiles, find where there are contacts with our pid and add this profile to us
func addClientToProfile(client *Client) {
	profiles.Range(func(key interface{}, value interface{}) bool {
		profile := value.(*Profile)
		if addClientToContacts(profile.Contacts, client, profile) {
			//if we have at least one of the profiles of this profile, we will go over them and send our status
			profile.clients.Range(func(key interface{}, value interface{}) bool {
				curClient := value.(*Client)
				sendMessage(curClient.Conn, TMESS_STATUS, cleanPid(client.Pid), "1")
				return true
			})
		}
		return true
	})
}

//run through all contacts and if there is a match, then we will add a link to the profile to this client
func addClientToContacts(contact *Contact, client *Client, profile *Profile) bool {
	res := false

	for contact != nil {
		if cleanPid(contact.Pid) == cleanPid(client.Pid) {
			client.profiles.Store(profile.Email, profile)
			res = true
		}

		if contact.Inner != nil {
			innerResult := addClientToContacts(contact.Inner, client, profile)
			if innerResult {
				res = true
			}
		}

		contact = contact.Next
	}

	return res
}

func checkStatuses(curClient *Client, first *Contact) {

	for first != nil {

		if first.Type != "fold" {
			_, exist := clients.Load(cleanPid(first.Pid))
			if exist {
				sendMessage(curClient.Conn, TMESS_STATUS, fmt.Sprint(cleanPid(first.Pid)), "1")
			} else {
				//sendMessage(curClient.Conn, TMESS_STATUS, fmt.Sprint(cleanPid(first.Pid)), "0")
			}
		}

		if first.Inner != nil {
			checkStatuses(curClient, first.Inner)
		}

		first = first.Next
	}

}

func saveCounters() {
	b, err := json.Marshal(&counterData)
	if err == nil {
		f, err := os.Create(FILE_COUNTERS)
		if err == nil {
			n, err := f.Write(b)
			if n != len(b) || err != nil {
				logAdd(MESS_ERROR, "Could not save counters: "+fmt.Sprint(err))
			}
			f.Close()
		} else {
			logAdd(MESS_ERROR, "Could not save counters: "+fmt.Sprint(err))
		}
	} else {
		logAdd(MESS_ERROR, "Could not save counters: "+fmt.Sprint(err))
	}
}

func loadCounters() {
	counterData.currentPos = time.Now()

	f, err := os.Open(FILE_COUNTERS)
	defer f.Close()
	if err == nil {
		b, err := ioutil.ReadAll(f)
		if err == nil {
			err = json.Unmarshal(b, &counterData)
			if err != nil {
				logAdd(MESS_ERROR, "Could not load counters: "+fmt.Sprint(err))
			}
		} else {
			logAdd(MESS_ERROR, "Could not load counters: "+fmt.Sprint(err))
		}
	} else {
		logAdd(MESS_ERROR, "Could not load counters: "+fmt.Sprint(err))
	}

	counterData.CounterClients[int(counterData.currentPos.Hour())] = 0
}

func addCounter(bytes uint64) {
	if options.Mode == NODE {
		sendMessageToMaster(TMESS_AGENT_DEL_CONNECT, fmt.Sprint(bytes))
	}

	counterData.mutex.Lock()
	defer counterData.mutex.Unlock()

	counterData.CounterBytes[int(counterData.currentPos.Hour())] = counterData.CounterBytes[int(counterData.currentPos.Hour())] + bytes
	counterData.CounterConnections[int(counterData.currentPos.Hour())] = counterData.CounterConnections[int(counterData.currentPos.Hour())] + 1

	counterData.CounterDayWeekBytes[int(counterData.currentPos.Weekday())] = counterData.CounterDayWeekBytes[int(counterData.currentPos.Weekday())] + bytes
	counterData.CounterDayWeekConnections[int(counterData.currentPos.Weekday())] = counterData.CounterDayWeekConnections[int(counterData.currentPos.Weekday())] + 1

	counterData.CounterDayBytes[int(counterData.currentPos.Day()-1)] = counterData.CounterDayBytes[int(counterData.currentPos.Day()-1)] + bytes
	counterData.CounterDayConnections[int(counterData.currentPos.Day()-1)] = counterData.CounterDayConnections[int(counterData.currentPos.Day()-1)] + 1

	counterData.CounterDayYearBytes[int(counterData.currentPos.YearDay()-1)] = counterData.CounterDayYearBytes[int(counterData.currentPos.YearDay()-1)] + bytes
	counterData.CounterDayYearConnections[int(counterData.currentPos.YearDay()-1)] = counterData.CounterDayYearConnections[int(counterData.currentPos.YearDay()-1)] + 1

	counterData.CounterMonthBytes[int(counterData.currentPos.Month()-1)] = counterData.CounterMonthBytes[int(counterData.currentPos.Month()-1)] + bytes
	counterData.CounterMonthConnections[int(counterData.currentPos.Month()-1)] = counterData.CounterMonthConnections[int(counterData.currentPos.Month()-1)] + 1
}

func updateCounterClient(add bool) {

	counterData.mutex.Lock()
	defer counterData.mutex.Unlock()

	if add {
		counterData.CounterClients[int(counterData.currentPos.Hour())] = counterData.CounterClients[int(counterData.currentPos.Hour())] + 1
	} else {
		counterData.CounterClients[int(counterData.currentPos.Hour())] = counterData.CounterClients[int(counterData.currentPos.Hour())] - 1
		return
	}

	count := counterData.CounterClients[int(counterData.currentPos.Hour())]

	if counterData.CounterDayWeekClients[int(counterData.currentPos.Weekday())] < count {
		counterData.CounterDayWeekClients[int(counterData.currentPos.Weekday())] = count
	}

	if counterData.CounterDayClients[int(counterData.currentPos.Day()-1)] < count {
		counterData.CounterDayClients[int(counterData.currentPos.Day()-1)] = count
	}

	if counterData.CounterDayYearClients[int(counterData.currentPos.YearDay()-1)] < count {
		counterData.CounterDayYearClients[int(counterData.currentPos.YearDay()-1)] = count
	}

	if counterData.CounterMonthClients[int(counterData.currentPos.Month()-1)] < count {
		counterData.CounterMonthClients[int(counterData.currentPos.Month()-1)] = count
	}
}

func swiftCounter() {
	counterData.mutex.Lock()
	defer counterData.mutex.Unlock()

	if time.Now().Hour() != counterData.currentPos.Hour() {
		now := time.Now()
		counterData.CounterBytes[time.Now().Hour()] = 0
		counterData.CounterConnections[time.Now().Hour()] = 0
		counterData.CounterClients[time.Now().Hour()] = counterData.CounterClients[counterData.currentPos.Hour()]

		if time.Now().Day() != counterData.currentPos.Day() {
			counterData.CounterDayWeekBytes[int(time.Now().Weekday())] = 0
			counterData.CounterDayWeekConnections[int(time.Now().Weekday())] = 0
			counterData.CounterDayWeekClients[time.Now().Weekday()] = counterData.CounterClients[int(counterData.currentPos.Hour())]

			counterData.CounterDayBytes[int(time.Now().Day()-1)] = 0
			counterData.CounterDayConnections[int(time.Now().Day()-1)] = 0
			counterData.CounterDayClients[time.Now().Day()-1] = counterData.CounterClients[int(counterData.currentPos.Hour())]

			counterData.CounterDayYearBytes[int(time.Now().YearDay()-1)] = 0
			counterData.CounterDayYearConnections[int(time.Now().YearDay()-1)] = 0
			counterData.CounterDayYearClients[time.Now().YearDay()-1] = counterData.CounterClients[int(counterData.currentPos.Hour())]

			if time.Now().Month() != counterData.currentPos.Month() {
				counterData.CounterMonthBytes[int(time.Now().Month()-1)] = 0
				counterData.CounterMonthConnections[int(time.Now().Month()-1)] = 0
				counterData.CounterMonthClients[time.Now().Month()-1] = counterData.CounterClients[int(counterData.currentPos.Hour())]
			}
		}

		saveCounters()
		counterData.currentPos = now
	}
}

func cleanPid(pid string) string {
	//todo can then be added here to delete and other characters
	return strings.Replace(pid, ":", "", -1)
}

func checkError(err error) {
	if err != nil {
		panic(err)
	}
}

func getMyIp() string {
	int, err := net.Interfaces()
	checkError(err)

	ip := net.IPv4zero.String()
	for _, i := range int {
		if (i.Flags&net.FlagLoopback == 0) && (i.Flags&net.FlagPointToPoint == 0) && (i.Flags&net.FlagUp == 1) {
			z, err := i.Addrs()
			checkError(err)

			for _, j := range z {
				x, _, _ := net.ParseCIDR(j.String())

				if x.IsGlobalUnicast() && x.To4() != nil {
					ip = x.To4().String()
					return ip
				}
			}
		}
	}

	return ip
}

func ping(conn *net.Conn) {
	success := true
	for success {
		time.Sleep(time.Second * WAIT_PING)
		success = sendMessage(conn, TMESS_PING)
	}
}
