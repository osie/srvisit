package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func processVersion(message Message, conn *net.Conn, curClient *Client, id string) {
	logAdd(MESS_INFO, id+" came version information")

	if len(message.Messages) != 1 {
		logAdd(MESS_ERROR, id+" not the correct number of fields")
		return
	}

	curClient.Version = message.Messages[0]
}

func processAuth(message Message, conn *net.Conn, curClient *Client, id string) {
	logAdd(MESS_INFO, id+" came the authorization")

	if len(message.Messages) != 1 {
		logAdd(MESS_ERROR, id+" not the correct number of fields")
		return
	}
	if len(message.Messages[0]) < 3 {
		time.Sleep(time.Millisecond * WAIT_IDLE)
		sendMessage(conn, TMESS_DEAUTH)
		logAdd(MESS_ERROR, id+" weak serial")
		return
	}

	s := getPid(message.Messages[0])
	logAdd(MESS_INFO, id+" generated pid")

	salt := randomString(LEN_SALT)

	value, exist := clients.Load(cleanPid(s))
	if exist {
		c := value.(*Client)
		if c.Conn != nil || (*c.Conn).RemoteAddr() == (*conn).RemoteAddr() {
			err := (*c.Conn).Close()
			if err != nil { //todo check the need for this
				logAdd(MESS_INFO, id+fmt.Sprint(err))
			}
			clients.Delete(cleanPid(s))
			c.Pid = ""
			c.Pass = ""
			c.Profile = nil
			exist = false
			updateCounterClient(false)
			logAdd(MESS_INFO, id+" removed a double")
		}
	}

	if !exist {
		if sendMessage(conn, TMESS_AUTH, s, salt) {

			curClient.Conn = conn
			curClient.Pid = s
			curClient.Serial = message.Messages[0]
			curClient.Salt = salt
			clients.Store(cleanPid(s), curClient)
			updateCounterClient(true)
			addClientToProfile(curClient)
			logAdd(MESS_INFO, id+" authorization is successful")
		}
	} else {
		time.Sleep(time.Millisecond * WAIT_IDLE)
		sendMessage(conn, TMESS_DEAUTH)
		logAdd(MESS_INFO, id+" authorization is failed, such pid is busy")
	}

}

func processNotification(message Message, conn *net.Conn, curClient *Client, id string) {
	logAdd(MESS_INFO, id+" notification has come")

	if len(message.Messages) != 2 {
		logAdd(MESS_ERROR, id+" not the correct number of fields")
		return
	}

	value, exist := clients.Load(cleanPid(message.Messages[0]))

	if exist == true {
		peer := value.(*Client)

		//todo it would be necessary somehow to be protected from a spam
		sendMessage(peer.Conn, TMESS_NOTIFICATION, message.Messages[1])
	}
}

func processConnect(message Message, conn *net.Conn, curClient *Client, id string) {
	logAdd(MESS_INFO, id+" we process the connection request")

	if len(message.Messages) < 2 {
		logAdd(MESS_ERROR, id+" not the correct number of fields")
		return
	}

	salt := curClient.Salt
	if len(message.Messages) == 3 {
		salt = message.Messages[2]
	}

	value, exist := clients.Load(cleanPid(message.Messages[0]))

	if exist == true {
		peer := value.(*Client)
		passDigest := message.Messages[1]

		code := randomString(CODE_LENGTH)
		connectPeers(code)

		//123
		//todo consider routes to nodes
		//check the version of clients
		//Send requests together with the address where connects

		//The easiest option is through the server both peers
		if sendMessage(curClient.Conn, TMESS_CONNECT, passDigest, salt, code, "simple", "client", peer.Pid) { //the one who receives the broadcast
			if sendMessage(peer.Conn, TMESS_CONNECT, passDigest, salt, code, "simple", "server", curClient.Pid) { //the one who broadcasts
				logAdd(MESS_INFO, id+" requested communication")
				return
			}
		}

		disconnectPeers(code)
		logAdd(MESS_ERROR, id+" Something went wrong")

	} else {
		logAdd(MESS_INFO, id+" there is no such feast")
		sendMessage(curClient.Conn, TMESS_NOTIFICATION, "there is no such feast")
	}
}

func processDisconnect(message Message, conn *net.Conn, curClient *Client, id string) {
	logAdd(MESS_INFO, id+" I received a request to disconnect")
	if len(message.Messages) != 1 {
		logAdd(MESS_ERROR, id+" not the correct number of fields")
		return
	}

	code := message.Messages[0]

	disconnectPeers(code)
}

func processPing(message Message, conn *net.Conn, curClient *Client, id string) {
	//logAdd(MESS_INFO, id + " came ping")
}

func processLogin(message Message, conn *net.Conn, curClient *Client, id string) {
	logAdd(MESS_INFO, id+" I received a request to authorize my profile")
	if len(message.Messages) != 2 {
		logAdd(MESS_ERROR, id+" not the correct number of fields")
		return
	}

	email := strings.ToLower(message.Messages[0])
	profile, ok := profiles.Load(email)
	if ok == true {
		if message.Messages[1] == getSHA256(profile.(*Profile).Pass+curClient.Salt) {
			logAdd(MESS_INFO, id+" profile authorization completed")
			sendMessage(conn, TMESS_LOGIN)

			curClient.Profile = profile.(*Profile)
			profile.(*Profile).clients.Store(cleanPid(curClient.Pid), curClient)
			processContacts(message, conn, curClient, id)
			return
		}
	} else {
		logAdd(MESS_ERROR, id+" there is no such accounting")
	}

	logAdd(MESS_ERROR, id+" authorization profile is not successful")
	sendMessage(conn, TMESS_NOTIFICATION, "Profile authorization failed!")
}

func processReg(message Message, conn *net.Conn, curClient *Client, id string) {
	logAdd(MESS_INFO, id+" I received a registration request")
	if len(message.Messages) != 1 {
		logAdd(MESS_ERROR, id+" not the correct number of fields")
		return
	}

	//check availability of accounting
	_, ok := profiles.Load(message.Messages[0])
	if ok == false {
		newProfile := Profile{}
		newProfile.Email = strings.ToLower(message.Messages[0])
		newProfile.Pass = randomString(PASSWORD_LENGTH)

		msg := []byte("Subject: Information from reVisit\r\n\r\nYour password is " + newProfile.Pass + "\r\n")
		err := smtp.SendMail(options.ServerSMTP+":"+options.PortSMTP, smtp.PlainAuth("", options.LoginSMTP, options.PassSMTP, options.ServerSMTP), options.LoginSMTP, []string{message.Messages[0]}, msg)
		if err != nil {
			logAdd(MESS_ERROR, id+" unable to send email with password: "+fmt.Sprint(err))
			sendMessage(conn, TMESS_NOTIFICATION, "unable to send email with password!")
			return
		}
		profiles.Store(newProfile.Email, &newProfile)
		sendMessage(conn, TMESS_REG, "success")
		sendMessage(conn, TMESS_NOTIFICATION, "Account is created, your password is in the mail!")
		logAdd(MESS_INFO, id+" created accounting")
	} else {
		//todo send a double to the post office
		logAdd(MESS_INFO, id+" such accounting already exists")
		sendMessage(conn, TMESS_NOTIFICATION, "This account already exists!")
	}

}

func processContact(message Message, conn *net.Conn, curClient *Client, id string) {
	logAdd(MESS_INFO, id+" came request for a contact")
	if len(message.Messages) != 6 {
		logAdd(MESS_ERROR, id+" not the correct number of fields")
		return
	}

	profile := curClient.Profile
	if profile == nil {
		logAdd(MESS_ERROR, id+" unauthorized profile")
		return
	}

	i, err := strconv.Atoi(message.Messages[0])
	if err == nil {
		profile.mutex.Lock()
		defer profile.mutex.Unlock()

		if i == -1 {
			i = getNewId(profile.Contacts)
		}

		if message.Messages[1] == "del" {
			profile.Contacts = delContact(profile.Contacts, i) //remove links to a contact
		} else {
			c := getContact(profile.Contacts, i)

			//if not, create
			if c == nil {
				c = &Contact{}
				if len(message.Messages[5]) == 0 { //if no parent is specified, then the root
					c.Next = profile.Contacts
					profile.Contacts = c
				}
			}

			if len(message.Messages[5]) > 0 { //change parent
				profile.Contacts = delContact(profile.Contacts, i) //remove links to a contact

				ip, err := strconv.Atoi(message.Messages[5]) //IndexParent looking for a new parent
				if err == nil {
					p := getContact(profile.Contacts, ip)
					if p != nil {
						c.Next = p.Inner
						p.Inner = c
					} else {
						c.Next = profile.Contacts
						profile.Contacts = c
					}
				} else {
					c.Next = profile.Contacts
					profile.Contacts = c
				}
			}

			c.Id = i
			c.Type = message.Messages[1]
			c.Caption = message.Messages[2]
			c.Pid = message.Messages[3]
			if len(message.Messages[4]) > 0 {
				c.Digest = message.Messages[4]
				c.Salt = curClient.Salt
			}
			message.Messages[0] = fmt.Sprint(i)

			//if such a pid online - add our profile there
			client, exist := clients.Load(cleanPid(message.Messages[3]))
			if exist {
				client.(*Client).profiles.Store(profile.Email, profile)
			}
		}

		//we will send all authorized changes
		profile.clients.Range(func(key interface{}, value interface{}) bool {
			sendMessage(value.(*Client).Conn, message.TMessage, message.Messages...)
			return true
		})

		processStatus(createMessage(TMESS_STATUS, fmt.Sprint(i)), conn, curClient, id)

		logAdd(MESS_INFO, id+" the operation with the contact is complete")
		return
	}
	logAdd(MESS_ERROR, id+" the operation with the contact failed")
}

func processContacts(message Message, conn *net.Conn, curClient *Client, id string) {
	logAdd(MESS_INFO, id+" I received a request to update my contacts")

	if curClient.Profile == nil {
		logAdd(MESS_ERROR, id+" the profile is not authorized")
	}

	//Send all contacts
	b, err := json.Marshal(curClient.Profile.Contacts)
	if err == nil {
		enc := url.PathEscape(string(b))
		sendMessage(conn, TMESS_CONTACTS, enc)
		logAdd(MESS_INFO, id+" sent contacts")

		processStatuses(createMessage(TMESS_STATUSES), conn, curClient, id)
	} else {
		logAdd(MESS_ERROR, id+" could not send contacts: "+fmt.Sprint(err))
	}
}

func processLogout(message Message, conn *net.Conn, curClient *Client, id string) {
	logAdd(MESS_INFO, id+" I received an exit request")

	if curClient.Profile == nil {
		logAdd(MESS_ERROR, id+" unauthorized profile")
		return
	}

	curClient.Profile.clients.Delete(cleanPid(curClient.Pid))
	curClient.Profile = nil
}

func processConnectContact(message Message, conn *net.Conn, curClient *Client, id string) {
	logAdd(MESS_INFO, id+" I received a request to connect to the contact")
	if len(message.Messages) != 1 {
		logAdd(MESS_ERROR, id+" not the correct number of fields")
		return
	}

	profile := curClient.Profile
	if profile == nil {
		logAdd(MESS_ERROR, id+" unauthorized profile")
		return
	}

	i, err := strconv.Atoi(message.Messages[0])
	if err == nil {
		p := getContact(profile.Contacts, i)
		if p != nil {
			processConnect(createMessage(TMESS_CONNECT, p.Pid, p.Digest, p.Salt), conn, curClient, id)
		} else {
			logAdd(MESS_ERROR, id+" there is no such contact in the profile")
			sendMessage(conn, TMESS_NOTIFICATION, "there is no such contact in the profile!")
		}
	} else {
		logAdd(MESS_ERROR, id+" conversion error of the identifier")
		sendMessage(conn, TMESS_NOTIFICATION, "conversion error of the identifier!")
	}
}

func processStatuses(message Message, conn *net.Conn, curClient *Client, id string) {
	logAdd(MESS_INFO, id+" I received a request for profile statuses")
	if len(message.Messages) != 0 {
		logAdd(MESS_ERROR, id+" not the correct number of fields")
		return
	}

	if curClient.Profile == nil {
		logAdd(MESS_ERROR, id+" unauthorized profile")
		return
	}

	checkStatuses(curClient, curClient.Profile.Contacts)
}

func processStatus(message Message, conn *net.Conn, curClient *Client, id string) {
	logAdd(MESS_INFO, id+" I received a request for contact status")
	if len(message.Messages) != 1 {
		logAdd(MESS_ERROR, id+" not the correct number of fields")
		return
	}

	if curClient.Profile == nil {
		logAdd(MESS_ERROR, id+" unauthorized profile")
		return
	}

	i, err := strconv.Atoi(message.Messages[0])
	if err == nil {
		contact := getContact(curClient.Profile.Contacts, i)
		if contact != nil {
			_, exist := clients.Load(cleanPid(contact.Pid))
			if exist {
				sendMessage(conn, TMESS_STATUS, contact.Pid, "1")
			} else {
				sendMessage(conn, TMESS_STATUS, contact.Pid, "0")
			}
		}
	}
}

func processInfoContact(message Message, conn *net.Conn, curClient *Client, id string) {
	logAdd(MESS_INFO, id+" I received a request for information about the contact")
	if len(message.Messages) != 1 {
		logAdd(MESS_ERROR, id+" not the correct number of fields")
		return
	}

	if curClient.Profile == nil {
		logAdd(MESS_ERROR, id+" unauthorized profile")
		return
	}

	i, err := strconv.Atoi(message.Messages[0])
	if err == nil {
		p := getContact(curClient.Profile.Contacts, i)
		if p != nil {
			value, exist := clients.Load(cleanPid(p.Pid))
			if exist == true {
				peer := value.(*Client)

				sendMessage(peer.Conn, TMESS_INFO_CONTACT, curClient.Pid, p.Digest, p.Salt)
			} else {
				logAdd(MESS_ERROR, id+" there is no such contact on the network")
				sendMessage(conn, TMESS_NOTIFICATION, "there is no such contact on the network!")
			}
		} else {
			logAdd(MESS_ERROR, id+" there is no such contact in the profile")
			sendMessage(conn, TMESS_NOTIFICATION, "there is no such contact in the profile!")
		}
	} else {
		logAdd(MESS_ERROR, id+" conversion error of the identifier")
		sendMessage(conn, TMESS_NOTIFICATION, "conversion error of the identifier!")
	}

}

func processInfoAnswer(message Message, conn *net.Conn, curClient *Client, id string) {
	logAdd(MESS_INFO, id+" I received a response to contact information")
	if len(message.Messages) < 1 {
		logAdd(MESS_ERROR, id+" not the correct number of fields")
		return
	}

	value, exist := clients.Load(cleanPid(message.Messages[0]))
	if exist == true {
		peer := value.(*Client)

		if peer.Profile != nil {
			sendMessage(peer.Conn, TMESS_INFO_ANSWER, message.Messages...)
			logAdd(MESS_INFO, id+" returned the answer")
		} else {
			logAdd(MESS_ERROR, id+" deauthorized profile")
		}
	} else {
		logAdd(MESS_ERROR, id+" there is no such contact on the network")
		sendMessage(conn, TMESS_NOTIFICATION, "there is no such contact on the network!")
	}

}

func processManage(message Message, conn *net.Conn, curClient *Client, id string) {
	logAdd(MESS_INFO, id+" came request for management")
	if len(message.Messages) < 2 {
		logAdd(MESS_ERROR, id+" not the correct number of fields")
		return
	}

	if curClient.Profile == nil {
		logAdd(MESS_ERROR, id+" unauthorized profile")
		return
	}

	i, err := strconv.Atoi(message.Messages[0])
	if err == nil {
		p := getContact(curClient.Profile.Contacts, i)
		if p != nil {
			value, exist := clients.Load(cleanPid(p.Pid))
			if exist == true {
				peer := value.(*Client)

				var content []string
				content = append(content, curClient.Pid, p.Digest, p.Salt)
				content = append(content, message.Messages[1:]...)

				sendMessage(peer.Conn, TMESS_MANAGE, content...)
			} else {
				logAdd(MESS_ERROR, id+" there is no such contact on the network")
				sendMessage(conn, TMESS_NOTIFICATION, "there is no such contact on the network!")
			}
		} else {
			logAdd(MESS_ERROR, id+" there is no such contact in the profile")
			sendMessage(conn, TMESS_NOTIFICATION, "there is no such contact in the profile!")
		}
	} else {
		logAdd(MESS_ERROR, id+" conversion error of the identifier")
		sendMessage(conn, TMESS_NOTIFICATION, "Error converting the identifier!")
	}
}

func processContactReverse(message Message, conn *net.Conn, curClient *Client, id string) {
	logAdd(MESS_INFO, id+" came a request to add to someone else's account")

	if len(message.Messages) < 3 {
		logAdd(MESS_ERROR, id+" not the correct number of fields")
		return
	}

	//Message[0] - login profile
	//Message[1] - digest
	//Message[2] - caption

	value, exist := profiles.Load(message.Messages[0])
	if exist {
		curProfile := value.(*Profile)
		if getSHA256(curProfile.Pass+curClient.Salt) == message.Messages[1] {
			i := getNewId(curProfile.Contacts)

			c := &Contact{}
			c.Next = curProfile.Contacts //add just yet to the root
			curProfile.Contacts = c

			c.Id = i
			c.Type = "node"
			c.Caption = message.Messages[2]
			c.Pid = curClient.Pid
			c.Digest = message.Messages[1]
			c.Salt = curClient.Salt

			//add this profile to an authorized list
			curClient.profiles.Store(curProfile.Email, curProfile)

			//we will send all authorized changes
			curProfile.clients.Range(func(key interface{}, value interface{}) bool {
				sendMessage(value.(*Client).Conn, TMESS_CONTACT, fmt.Sprint(i), "node", c.Caption, c.Pid, "", "-1")
				sendMessage(value.(*Client).Conn, TMESS_STATUS, fmt.Sprint(i), "1")
				return true
			})

			logAdd(MESS_INFO, id+" the operation with the contact is complete")
			return
		}
	}

	logAdd(MESS_ERROR, id+" could not add contact to another's profile")
}
