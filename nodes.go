package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
)

func masterServer() {
	logAdd(MESS_INFO, "masterServer started")

	ln, err := net.Listen("tcp", ":"+options.MasterPort)
	if err != nil {
		logAdd(MESS_ERROR, "masterServer could not take port")
		os.Exit(1)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			logAdd(MESS_ERROR, "masterServer could not take a socket")
			break
		}

		go ping(&conn)
		go masterHandler(&conn)
	}

	ln.Close()
	logAdd(MESS_INFO, "masterServer stopped")
}

func masterHandler(conn *net.Conn) {
	id := randomString(MAX_LEN_ID_LOG)
	logAdd(MESS_INFO, id+" masterServer received the connection")

	var curNode Node

	reader := bufio.NewReader(*conn)

	for {
		buff, err := reader.ReadBytes('}')

		if err != nil {
			logAdd(MESS_ERROR, id+" buffer read error")
			break
		}

		logAdd(MESS_DETAIL, id+fmt.Sprint(" buff ("+strconv.Itoa(len(buff))+"): "+string(buff)))

		//remove rubbish
		if buff[0] != '{' {
			logAdd(MESS_INFO, id+" masterServer remove garbage")
			if bytes.Index(buff, []byte("{")) >= 0 {
				buff = buff[bytes.Index(buff, []byte("{")):]
			} else {
				continue
			}
		}

		var message Message
		err = json.Unmarshal(buff, &message)
		if err != nil {
			logAdd(MESS_ERROR, id+" parse error json")
			time.Sleep(time.Millisecond * WAIT_IDLE)
			continue
		}

		logAdd(MESS_DETAIL, id+" "+fmt.Sprint(message))

		//process the received message
		if len(processingAgent) > message.TMessage {
			if processingAgent[message.TMessage].Processing != nil {
				go processingAgent[message.TMessage].Processing(message, conn, &curNode, id) //from one agent there can be a lot of messages, do not slow them down
			} else {
				logAdd(MESS_INFO, id+" there is no handler for the message")
				time.Sleep(time.Millisecond * WAIT_IDLE)
			}
		} else {
			logAdd(MESS_INFO, id+" unknown message")
			time.Sleep(time.Millisecond * WAIT_IDLE)
		}

	}
	(*conn).Close()

	//if there is id means most likely there is in the map
	if len(curNode.Id) == 0 {
		nodes.Delete(curNode.Id)
	}

	logAdd(MESS_INFO, id+" masterServer lost connection to agent")
}

func nodeClient() {

	logAdd(MESS_INFO, "nodeClient started")

	for {
		conn, err := net.Dial("tcp", options.MasterServer+":"+options.MasterPort)
		if err != nil {
			logAdd(MESS_ERROR, "nodeClient could not connect: "+fmt.Sprint(err))
			time.Sleep(time.Second * WAIT_IDLE_AGENT)
			continue
		}

		master = &conn

		hostname, err := os.Hostname()
		if err != nil {
			hostname = randomString(MAX_LEN_ID_NODE)
		}
		sendMessage(&conn, TMESS_AGENT_AUTH, hostname, options.MasterPassword)

		go ping(&conn)

		reader := bufio.NewReader(conn)
		for {
			buff, err := reader.ReadBytes('}')

			if err != nil {
				logAdd(MESS_ERROR, "nodeClient buffer read error: "+fmt.Sprint(err))
				break
			}

			logAdd(MESS_DETAIL, fmt.Sprint("buff ("+strconv.Itoa(len(buff))+"): "+string(buff)))

			//remove rubbish
			if buff[0] != '{' {
				logAdd(MESS_INFO, "nodeClient remove garbage")
				if bytes.Index(buff, []byte("{")) >= 0 {
					logAdd(MESS_DETAIL, fmt.Sprint("buff ("+strconv.Itoa(len(buff))+"): "+string(buff)))
					buff = buff[bytes.Index(buff, []byte("{")):]
				} else {
					continue
				}
			}

			var message Message
			err = json.Unmarshal(buff, &message)
			if err != nil {
				logAdd(MESS_ERROR, "nodeClient parse error json: "+fmt.Sprint(err))
				time.Sleep(time.Millisecond * WAIT_IDLE)
				continue
			}

			logAdd(MESS_DETAIL, fmt.Sprint(message))

			//process the received message
			if len(processingAgent) > message.TMessage {
				if processingAgent[message.TMessage].Processing != nil {
					go processingAgent[message.TMessage].Processing(message, &conn, nil, randomString(MAX_LEN_ID_LOG))
				} else {
					logAdd(MESS_INFO, "nodeClient no handler for message")
					time.Sleep(time.Millisecond * WAIT_IDLE)
				}
			} else {
				logAdd(MESS_INFO, "nodeClient unknown message")
				time.Sleep(time.Millisecond * WAIT_IDLE)
			}

		}
		conn.Close()
	}
	//logAdd(MESS_INFO, "nodeClient stopped") //unattainable???
}

func processAgentAuth(message Message, conn *net.Conn, curNode *Node, id string) {
	logAdd(MESS_INFO, id+" the authorization of the agent came")

	if options.Mode == REGULAR {
		logAdd(MESS_ERROR, id+" non-agent mode")
		(*conn).Close()
		return
	}

	if options.Mode == NODE {
		logAdd(MESS_ERROR, id+" came feedback on authorization")
		return
	}

	time.Sleep(time.Millisecond * WAIT_IDLE)

	if len(message.Messages) != 2 {
		logAdd(MESS_ERROR, id+" not the correct number of fields")
		(*conn).Close()
		return
	}

	if message.Messages[1] != options.MasterPassword {
		logAdd(MESS_ERROR, id+" wrong password")
		(*conn).Close()
		return
	}

	curNode.Conn = conn
	curNode.Name = message.Messages[0]
	curNode.Id = randomString(MAX_LEN_ID_NODE)
	curNode.Ip = (*conn).RemoteAddr().String()

	if sendMessage(conn, TMESS_AGENT_AUTH, curNode.Id) {
		nodes.Store(curNode.Id, curNode)
		logAdd(MESS_INFO, id+" agent authorization is successful")
	}
}

func processAgentAnswer(message Message, conn *net.Conn, curNode *Node, id string) {
	if options.Mode != NODE {
		logAdd(MESS_ERROR, id+" non-agent mode")
		return
	}

	logAdd(MESS_INFO, id+" I received a response to the agent's authorization")

	//todo add processing
}

func processAgentAddCode(message Message, conn *net.Conn, curNode *Node, id string) {
	if options.Mode != NODE {
		logAdd(MESS_ERROR, id+" non-agent mode")
		return
	}

	logAdd(MESS_INFO, id+" came information about the creation of the session")

	if len(message.Messages) != 1 {
		logAdd(MESS_ERROR, id+" not the correct number of fields")
		return
	}

	connectPeers(message.Messages[0])
}

func processAgentDelCode(message Message, conn *net.Conn, curNode *Node, id string) {
	if options.Mode != NODE {
		logAdd(MESS_ERROR, id+" non-agent mode")
		return
	}

	logAdd(MESS_INFO, id+" information about deleting a session")

	if len(message.Messages) != 1 {
		logAdd(MESS_ERROR, id+" not the correct number of fields")
		return
	}

	disconnectPeers(message.Messages[0])
}

func processAgentNewConnect(message Message, conn *net.Conn, curNode *Node, id string) {
	if options.Mode != MASTER {
		logAdd(MESS_ERROR, id+" non-agent mode")
		return
	}

	logAdd(MESS_INFO, id+" information about a new connection")

	//if len(message.Messages) != 1 {
	//	logAdd(MESS_ERROR, id + " not the correct number of fields")
	//	return
	//}
	//
	//code := message.Messages[0]
	//
	//value, exist := channels.Load(code)
	//if exist == false {
	//	logAdd(MESS_ERROR, id + " do not wait for such a connection " + code)
	//	disconnectPeers(code)
	//	return
	//}
	//peers := value.(*dConn)
	//
	//peers.mutex.Lock()
	//if peers.node[0] == nil {
	//	peers.node[0] = curNode
	//} else if peers.pointer[1] == nil {
	//	peers.node[1] = curNode
	//}
	//peers.mutex.Unlock()
	//
	////we must wait for two connections
	//var cWait = 0
	//for (peers.node[0] == nil || peers.node[1] == nil) && cWait < WAIT_COUNT {
	//	logAdd(MESS_INFO, id + " we are waiting for a feast for " + code)
	//	time.Sleep(time.Millisecond * WAIT_IDLE)
	//	cWait++
	//}
	//
	////if you did not wait for one of the feasts
	//for peers.node[0] == nil || peers.node[1] == nil {
	//	logAdd(MESS_ERROR, id + " did not wait for a feast for " + code)
	//	disconnectPeers(code)
	//	return
	//}
	//
	////if they are from the same agent, then nothing
	//if peers.node[0].Id == peers.node[1].Id {
	//	logAdd(MESS_INFO, id + " feasts from one agent " + code)
	//	return
	//}
	//
	//logAdd(MESS_INFO, id + " sent a request to connect the agent to the agent " + code)
}

func processAgentDelConnect(message Message, conn *net.Conn, curNode *Node, id string) {
	if options.Mode != MASTER {
		logAdd(MESS_ERROR, id+" non-agent mode")
		return
	}

	logAdd(MESS_INFO, id+" information about the connection removal")

	if len(message.Messages) != 1 {
		logAdd(MESS_ERROR, id+" not the correct number of fields")
		return
	}

	disconnectPeers(message.Messages[0])
}

func processAgentAddBytes(message Message, conn *net.Conn, curNode *Node, id string) {
	if options.Mode != MASTER {
		logAdd(MESS_ERROR, id+" non-agent mode")
		return
	}

	logAdd(MESS_INFO, id+" came information statistics")

	if len(message.Messages) != 1 {
		logAdd(MESS_ERROR, id+" not the correct number of fields")
		return
	}

	bytes, err := strconv.Atoi(message.Messages[0])
	if err == nil {
		addCounter(uint64(bytes))
	}
}

func sendMessageToNodes(TMessage int, Messages ...string) {
	nodes.Range(func(key interface{}, value interface{}) bool {
		node := value.(*Node)
		return sendMessage(node.Conn, TMessage, Messages...)
	})
}

func sendMessageToMaster(TMessage int, Messages ...string) {
	sendMessage(master, TMessage, Messages...)
}
