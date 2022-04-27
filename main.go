package main

import (
	"fmt"
	"net"
	"bufio"
	_"os"
	"strings"
	_"io"
	"log"
	"regexp"
	//"encoding/json"
	"golang.org/x/crypto/ssh"
)

var (
	//conn net.Conn
	saes	map[string]string
)

type resultHSS struct {
	IMSI	string					`json:"imsi"`
	IMEI	string					`json:"imei"`
	ISDN	string					`json:"isdn"`
	MMEUpdateLocationTime string	`json:"last_registration4G"`
	PSUPLTIME	string				`json:"last_registration3G"`
	CSUPLTIME	string				`json:"last_registration2G"`
	VlrNum		string				`json:"vlr_city"`
	APN			string				`json:"apn"`
	PDNGWHOST	string				`json:"pgw"`
}

type resultSAE struct {
	IPAddress		string			`json:"ip_addrress"`
	RATType			string			`json:"rat_type"`
	SessionProfile	string			`json:"session_profile"`
	Location		string			`json:"location"`
	Uplink			string			`json:"up_link"`
	Downlink		string			`json:"down_link"`
	PCCRule			string			`json:"pcc_rule"`
}
type networkElement struct {
	host 		string
	conn 		net.Conn
}

type sae struct {}

type Connection struct {
	host 			string
	sshClient		*ssh.Session
}


func main() {

	cmd2 := fmt.Sprintf(`fsclish -c "show ng trace data-base-dump filter msisdn %s"`, "5919004103")
	conn := NewConnection("user", "pass", "IP:22", "ssh")
	sae := newSAE()
	resp, _ := conn.sendCmd(cmd2)
	data := sae.showDataBaseDump(string(resp))
	fmt.Printf("%#v", data)
}

func sshSession(user, password, addr string) (*ssh.Session, error) {
	//var hostKey ssh.PublicKey
	sshConfig := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.HostKeyCallback(func(hostname string, remote net.Addr, key ssh.PublicKey) error { return nil }),
		//HostKeyCallback: ssh.FixedHostKey(hostKey),
	}

	conn, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		log.Panic(err)
	}
	session, err := conn.NewSession()
	if err != nil {
		log.Panic(err)
	}
	//defer session.Close()

	modes := ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}

	err = session.RequestPty("xterm", 80, 40, modes)
	if err != nil {
		log.Panic(err)
	}
	
	return session, nil
}

func NewConnection(user, password, addr, _type string) (*Connection) {
	session, err := sshSession(user, password, addr)
	if err != nil {
		log.Panic(err)
	}
	return &Connection {
		host: addr,
		sshClient: session,
	}
}

func (c *Connection) sendCmd(cmd string) ([]byte, error) {

	output, err := c.sshClient.Output(cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to execute command '%s' on server: %v", cmd, err)
	}

	return output, err
}

func newSAE() *sae {
	return &sae{}
}

func (sae *sae) showDataBaseDump(data string) resultSAE {
	r := resultSAE{}
	reSAE := regexp.MustCompile(`(?m)^([\s\|]*)?([\w\- \(\)\/]+)\s+= ([\w\- \:\.\|\&=\[\/,\]]+)`)
	reIP := regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)
	groups := reSAE.FindAllStringSubmatch(data, -1)
	for _, group := range groups {
		switch group[2] {
		case "assigned IP address":
			r.IPAddress = reIP.FindString(group[3])
		case "RAT type":
			r.RATType = group[3]
		case "session profile name":
			r.SessionProfile = group[3]
		case "geographic location":
			r.Location = group[3]
		case "Aggregate Maximum Bitrate Uplink":
			r.Uplink = group[3]
		case "Aggregate Maximum Bitrate Downlink":
			r.Downlink = group[3]
		case "Pcc-rule-base(s)":
			r.PCCRule = group[3]
		}
	}
	return r
}

func newNE() *networkElement {


	return &networkElement{
		host:  "10.74.150.202:7776",
	}
}
func (ne *networkElement) loginHSS() {
	c, err := net.Dial("tcp4", ne.host)
	//defer c.Close()
	if err != nil {
			fmt.Println(err)
			return
	}
	ne.conn = c

	cmd := `LGI: HLRSN=1, OPNAME="USER", PWD="PWD";`
	resp, err := ne.sendCmd(cmd)
	if err != err {
		return
	}
	if strings.Index(resp, "incorrect") > 0 {
		log.Fatalln("RETCODE = 1013 Username or password incorrect")
		
	}
	return
}

func (ne *networkElement) getDatas(data string) (resultHSS) {
	r := resultHSS{}
	reHSS := regexp.MustCompile(`(?m)^(?P<KEY>[ ]*)?([\w\- ]+)\s+= ([\w\- \:\.\|\&]+)`)
	res := reHSS.FindAllStringSubmatch(data, -1)
	for _, line := range res {
		switch line[2] {
		case "IMSI":
			r.IMSI = line[3]
		case "IMEI":
			r.IMEI = line[3]
		case "ISDN":
			r.ISDN = line[3]
		case "MME-UpdateLocation-Time":
			r.MMEUpdateLocationTime = line[3]
		case "PSUPLTIME":
			r.PSUPLTIME = line[3]
		case "CSUPLTIME":
			r.CSUPLTIME = line[3]
		case "VlrNum":
			r.VlrNum = line[3]
		case "APN":
			r.APN = line[3]
		case "PDNGWHOST":
			r.PDNGWHOST = line[3]

		}
		//fmt.Printf("%s-> %s\n", line[2], line[3])
	}
	return r
}

func (ne *networkElement) sendCmd(cmd string) (string, error) {
	_, err := ne.conn.Write([]byte(cmd))
	if err != nil {
		println("Write the server failed:", err.Error())
		return "", err
	}
	resp, err := serverReader(ne.conn)
	return resp, nil
}

func serverReader(c net.Conn) (string, error) {
	cbuf := bufio.NewReader(c)
	//var lines []string
	var lines string
	for {
		//reply := make([]byte, 512)
		//_, err := c.Read(reply)
		line, err := cbuf.ReadString('\n')
		if err != nil {
			return "", err
		}

		lines += line
		
		if strings.Index(line, "END") > 0 {

			break
		}
	}
	return lines, nil
}
