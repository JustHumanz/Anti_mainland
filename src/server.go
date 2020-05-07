package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"syscall"
	"unsafe"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"github.com/oschwald/geoip2-golang"
)
func sshServer(ch chan Attempt) {
	var Xinjiang, brrr string
	Xinjiang = `
动态网自由门 天安門 天安门 法輪功 李洪志 Free Tibet 六四天安門事件 The Tiananmen Square protests of 1989 天安門大屠殺 The Tiananmen Square Massacre 反右派鬥爭 The Anti-Rightist Struggle 大躍進政策 The Great Leap Forward 文化大革命 The Great Proletarian Cultural Revolution 人權 Human Rights 民運 Democratization 自由 Freedom 獨立 Independence 多黨制 Multi-party system 台灣 臺灣 Taiwan Formosa 中華民國 Republic of China 西藏 土伯特 唐古特 Tibet 達賴喇嘛 Dalai Lama 法輪功 Falun Dafa 新疆維吾爾自治區 The Xinjiang Uyghur Autonomous Region 諾貝爾和平獎 Nobel Peace Prize 劉暁波 Liu Xiaobo 民主 言論 思想 反共 反革命 抗議 運動 騷亂 暴亂 騷擾 擾亂 抗暴 平反 維權 示威游行 李洪志 法輪大法 大法弟子 強制斷種 強制堕胎 民族淨化 人體實驗 肅清 胡耀邦 趙紫陽 魏京生 王丹 還政於民 和平演變 激流中國 北京之春 大紀元時報 九評論共産黨 獨裁 專制 壓制 統一 監視 鎮壓 迫害 侵略 掠奪 破壞 拷問 屠殺 活摘器官 誘拐 買賣人口 遊進 走私 毒品 賣淫 春畫 賭博 六合彩 天安門 天安门 法輪功 李洪志 Winnie the Pooh 劉曉波动态网自由门
lllooooddoolllcckXNNNNWWWWWWWWXkddoooooollllooddddddddddddddddxkOOOOOOOOOOOOOOOOOOOO0000000
lllooodoollccccoKNNNNWWWWWWWN0ddddooolc::;;;::clldodddodddxkkOOOOOOOOOOOOOOOOOOOOOOO0000000
lloooollccccccckXNNNWWWWWWWXxdoc;,...............';:clodxkOOOOOOOOOOOOOOOOOOOOOOOOO00000000
oolllcccccccc:lKNNNWWWWWWN0o:.......        ....'..'',;cllldkOOOO000OOOOOOOOOOOOOOO00000000
lllccccccc:::;xXNWWWWWWWXd,.......            ...'...',;:llccdxkOO000OOOOOOOOOOOOOO00000000
lllcccc::;;;;cKNNWWWWWWO;.                      ..',,,;;;ccc::lcdkO00OOOOOOOOOOOOO000000000
cccc::;;;;;:ckXNWWWWW0:.               .. .....  .',;,;,,';;,,:lloO00OOOOOOOOOOOOO000000000
c::;;;;;:cccoKNNWWWWO'..     ..     ................. .....;,';cclkO0OOOOOOOOOOOO0000000000
;;;;::ccccclkXNWWWWx...  ..........    . ..... ..      ....''';::lox0OOOOOOOOOOOOO000000000
;:ccccccclldKNNWWWW:..  ...............'...'',;;;,,'.....''.,;;;;,cd0OOOOOOOOOOOOO000000000
cccccclllookXNNWWWWl.  ......coxkO0KXXXXX0xdk00KKK0Oxddddoc;;::::cccxOOOOOOOOOOOOO000000000
cclllloooodKNNOxOKNd.   ..,:k00KKKXXNNWWWWWWWWWNWNNNXXXXK0Ol,''''..'dOOOOOOOOOOOOOOO0000000
llloooooookXKdoddodl.   .':d00KKKXXXXXNWWWWWWWWWWNNNXXNXXKKkc:,'....dOOOOOOOOOOOOOO00000000
looooooood0Oooooooo:..  .,oO00KKKKXXXNNNNNWWWWWWNXXXXXXXKKKOd:'...':OOOOOOOOOOOOOOOOO000000
oooooooddkxllooooooc..  .;dOO00KXXNNNNWWWWWWWWWWNNNNXNXKKKK0xc,...'xOOOOOOOOOOOOOOO000000O0
ooodddxxxdcloooodooc'...'dkOO0KKK0KKXNNNWWWWWWWWWNNNNNNXKKK0kc....:OOOOOOOOOOOOOOOO000000O0
ddxxxxxxdclooooooool;...okO0OO0Oo:,,;k0KXNNNNXNXK0o;,;cx0KKK0O:..:xOOOOOOOOOOOOOOOO0000OOOO
dxxxxxxxocloooox0XNWWX0ldxk000kdk00000K00KNNNKKKKKKK0K0xx0KKK0xox0KXXXKOOOOOOOOOOOOOOOOOOOO
dxxxxxxxcloooOWMMMWWWWNdoxkOOkxxdo;',ckkkKNNX0kOxdodOKKK0KKK00KKXXKXNWMMXOOOOOOOOOOOOOOOOOO
xxxxxkxoclooXWNNNXXXXXKddxk0KKKKXK0xox0K0KNWX0OOdkl,;dkOk0K0OO0KKKKXNNWMMXOOOOOOOOOOOOOOOOO
xxxxxkdcloo0WNNXKKKKKK0ddxkO0KXXKKKKKXNXXXNNNXXXKKK00KXNXXKK0000KKKXXXNWMM0OOOOOOOOOOOOOOOO
xxxxkxocoooKK0KKKKK000OdoxkO0KXXNXXXNNNNK0O00KNNNNNNNNWWNXK00O00KKKKXXNWMM0OOOOOOOOOOOOOOOO
xxxxkdllooox0OO0000OO0kooxxk0KXNNWNXKd;'...''',:xXNWWWWNXK0OOOO0KKKKXXNWMXOOOOOOOOOOOOOOOOO
xxxxxllooooodxxkkkkxdddodxxkO0KXXXKkc............lOKNNNXXK0OOkO00KKKXNMMXOOOOOOOOOOOOOOOOOO
xxxxdlooooooooooooollclooxxdkO0KK0k0K.       ...,0kxO0KK0OkkkkO00KXXNNX0OOOOOOOOOOOOOOOOOOO
xxxxlloooolloooooolllcllodxdoxOOOOKXXOo;'...''cdOKKOxOOOkxxkkkkOOO00OOOOOOOOOOOOOOOOOOOOOOO
xxxolooollllooooooollcclldxxxkkkk0000KK0OOkkO0KXXK00OkkkkxkkkxkOOOO00OOOOOOOOOOOOOOOOOOOOOO
xxdlloolllloooooooollcccclxxdkOOkdlllodxxxO0kdddodxkO0OOxkOkxxkOOOOOOOOOOOOOOOOOOOOOOOO0OOO
xxololllloooooooooollcccccoxdxO0k0KKkoclodoooolok0KO00OxxkxddkkkOOOOOOOOOOOOOOOOOOOOOOO0OOO
xdlollllooooooooooolcccccc:colxO0KKKKK0kxxxkxkOKXKK0Okdoddoo:.:kkkOOOOOOOOOOOOOOOOOOOOOOOOO
doollllooooooooooollccccccc:;::oxOKKKK0OOkkkO0KKK0K0xlodoodOO.,;dkOOOOOOOOOOOOOOOOOOOOOOOOO
oolllloooooooooooolllccccccc:::::lk0KXXXXNNNXXXXKKOoxxxxdxOMMc,,;:dkOOOOOOOOOOOOOOOOOOOOOOO
oooooooooooooooooolllcccccl;.l:clccok0KXKXXXXXK0Oxx0OOkkk0MMX,,,,,;:lxOOOOOOOOOOOOOOOOOOOOO
ooodxoooooooooooooolllclc:'.:WoclolccldxkOOOOkxddkOkkkk0WMMMc;,,,;;;;;;cldxkOOOOOOOOOO00OO0
ooxXKdooooooooooooooolc;,'..KMMOllooollllloodddxkkkO0XMMMMMl,,,,,;,,;;;;,,;;:ldxOOOOO000O00
oxXWNdooooooooooolc;,,''''.:WMMMM0ddoooooddxkkkO0KNMMMMMMMd;;;;,;;;;;;,;,,,,,,;;:codxO00O00
kKWWWOddooooool:,''''''''''KMMMMMMMNOxoooox0XNMMMMMMMMMMM0:;;;;;;;;;;;;;;;,,,,,,,;;;:ccodxO
WWWWWWNNNXOo;''''''''''''''MMMMMMMMMMMX0OXMMMMMMMMMMMMMMW:;;;;;;;;;;;;,'...,,,,,,,;;;;;;::c
WWWWWWXkl;''''..''''''''',:MMMMMMMMXKNWMMWMMMMMMMMMMMMMMo::;;;;;;;;;,..',,,,;;,,,,,;,,;;;;;
WWWKxc,'''''''........'',;dMMMMMMMXxxKWWMWNXMMMMMMMMMMMk::;;;:::cllll::;;;;;;;;;;;;;;;;;;;;
Od:,''''''''''''''.'''.',;kMMMMMMMWNk0WMWK00XMMMMMMMMMX:::;;:::d0lkoK0::::;;;;;;;;;;;;;;;;;
'''''''''''.''''''''...',;OMMMMMMMMMMOWN0KMMMMMMMMMMMMc:::;::::kOkkkk0:::',::::::::::::::::
.''''''''''''',''''''..';;0MMMMMMMMMNNMWKWMMMMMMMMMMMo::::::::::occclcc:';::::::::::::c:::,
Fuck off Chinese botnet

`

	brrr = `
	MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
	MMMMMMMMMMMMMMMMMMKxddddxkOOdooooddxO0XNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
	MMMMMMMMMW0kddooooooooooooooooooooooooodkxdxO0NMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
	MMMMMMNKOoooooooooooxOOoooooooooooooooooOK0xooodKWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
	MMMMxoooooooooooooooooooooooooooooooooooooodOkoooodONMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
	MMMKdooooooooooooooooodoodxooooooodooooddoooooooooooox0MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
	MMdooooooooooooooooodddx0xdOOO0OooookNMMMMN0xoooooooodxdkNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
	MMKooooo;dNNNNNK0kx0MMMMMMNNWWWWNOkNMMMMMMMMMW0xdooooodXxdMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
	MMMdoool:MMNXXXXXXXXXXX0OO0NMMMWWWNXXK0000KNMMMMM0xx0doddoWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
	MMMkooooOMWWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNkoooKMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
	MMMMW0xcKMMMMMMMMMMMMMMMMX00KKKK00KNWMMMMMMMMMMMMMMMMkoxOMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
	MMMMMMW,XMMKKK00OO0000O0XWMMMMMMMMMMNKOO0XNMMMMMMMMMMMcXMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
	MMMMMMW;NMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNXXXWMMMMMMMkoMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
	MMMMMMW;X0XKOOWWNMMMMNMMMMMMMMMMMWNMMMMMMMMMMMMMMMMMMMWcMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
	MMMMMMW:MMNOxO0kk0KOXKKkOMMMWMMK0:cd;cdocodd0WXNMMMMMMMKdMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
	MMMMMMXdMMMMMMMMMMMMOMMN0O0xOOXXMMWMMMMMOdloodxkkxdMMMMMKdMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
	MMMMMMcoMMMMMMMMMMMM:XMMMMMMMMMMMMMNKk:. .ldccKMMMNMMMMMMNlMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
	MMMMMW,XN:    ;dcl0N;KMMMMMMMMMMMXO.c     OMddMMMMMMMMMMMMWoWMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
	MMMMMxkMMO..  ;kkc0KcMMMMMMMMMMMMMMdo:;;,;loXMMMMMMMMMMMMMMMoMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
	MMMMOlMMMMO0KMMMMKdxWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM0xMMMMMMMMMMMMMMMMMMMMMMMMMMMM
	MMMMoKMMMMMMMMMklXMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMoNMMMMMMMMMMMMMMMMMMMMMMMMMMM
	MMMMOkMMMMMMMMMNlMMMMMMMMMMMMMMMMW0xdXMMMMMMMMMWMMMMMMMMMMMMMxdMMMMMMMMMMMMMMMMMMMMMMMMMMM
	MMMMOoMMMMMMMMMMlXMMMMMMMMMMMMMMMMMMM:NMMMMMMMNkddddWMMMMMMMMxcMMMMMMMMMMMMMMMMMMMMMMMMMMM
	MMMMMl;MMMMMMMMMN;00xKMMMXdoKMMK0K0dxKMMMMMMMMMMMMMMMMMMMMMMMxcMMMMMMMMMMMMMMMMMMMMMMMMMMM
	MMMMMM;0MMMOlxMMMNk0WMMMMMMMMMMMMMMMMMMx:xOXMMMMMMMMMMMMMMMMMxcMMMMMMMMMMMMMMMMMMMMMMMMMMM
	MMMMMMockkkXMMMMMMMMMMMMMMMMMMMMMMMMWMMMMNK0OkxxNMMMMMMMMMMMMK'NMMMMMMMMMMMMMMMMMMMMMMMMMM
	MMMMMMMx:KMMMxk0l:ccok00KNWWWXKkocNM,WMMMMMMMMMMWMMMMMMMMMMMMMd:MMMMMMMMMMMMMMMMMMMMMMMMMM
	MMMMMMMMMxldcKMMMMMMW0OkxooooxkONMMMdlMMMMMMMMMMMMMMMMMMMMMMMMM:xMMMMMMMMMMMMMMMMMMMMMMMMM
	MMMMMMMMMMMNkodNMMMMMMMMMMMMMMMMMMMMMdlMMMMMMMMMMMMMMMMMMMMMMMMO.MMMMMMMMMMMMMMMMMMMMMMMMM
	MMMMMMMMMMMMMMX:oMMMMMMMMMMMMMMMMMMMMWcWMMMMMMMMMMMMMMMMMMMMMMMX'NMMMMMMMMMMMMMMMMMMMMMMMM
	MMMMMMMMMMMMMMMMl;OMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMk;XMMMMMMMMMMMMMMMMMMMMMMM
	MMMMMMMMMMMMMMMMMMOc;xNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM0.0MMMMMMMMMMMMMMMMMMMMMM
	MMMMMMMMMMMMMMMMMMMWXXl;coxxo0MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMX'KMMMMMMMMMMMMMMMMMMMMM
	MMMMMMMMMMMMMMMMMMMMMMMMMMMM'lxMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMX:xMMMMMMMMMMMMMMMMMMMM
	MMMMMMMMMMMMMMMMMMMMMMMMMMMK;MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMKo0MMMMMMMMMMMMMMMMMM
	MMMMMMMMMMMMMMMMMMMMMMMMMMW;0MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMOl0MMMMMMMMMMMMMMMM
	MMMMMMMMMMMMMMMMMMMMMMMMMX;KMMMMMMMMN;MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMkcdXMMMMMMMMMMMMM
	MMMMMMMMMMMMMMMMMMMMMMMMkcWMMMMMMMMMMckMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMW0ko,'ONWMMMMMMMMM
	MMMMMMMMMMMMMMMMKOOOxkxlxMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWNK0kkkxlcdO0WMMM
	MMMMMMMMMMMMOddx0NWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMW0o;kM
	MMMMMMMMMXooXMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMXX
	MMMMMMMWkOMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
	MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
haha honeypot go brrrrrrrr
	
`
db, err := geoip2.Open("GeoLite2-Country.mmdb")
if err != nil {
    log.Fatal(err)
}
defer db.Close()

	config := ssh.ServerConfig{
		ServerVersion: "SSH-2.0-OpenSSH_8.2",
		BannerCallback: func (c ssh.ConnMetadata) (string)  {
			ip, _,_ := net.SplitHostPort(c.RemoteAddr().String())
			record, err := db.Country(net.ParseIP(ip))
			if err != nil {
				fmt.Print(err)
			}
			if record.Country.IsoCode == "CN" {
				return Xinjiang
			} else {
				return brrr
			}
			//fmt.Printf("country_short: %s\n", record.Country.IsoCode)
			
		},
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			logrus.Infof("Logon attempt: host=%s version=%s user=%q pass=%q", c.RemoteAddr(), c.ClientVersion(), c.User(), string(pass))

			source, _, err := net.SplitHostPort(c.RemoteAddr().String())
			if err != nil {
				source = c.RemoteAddr().String()
			}

			ch <- Attempt{
				User:        c.User(),
				Password:    string(pass),
				Source:      source,
				Version:     string(c.ClientVersion()),
				Application: "ssh",
			}

			if *alwaysDeny {
				return nil, fmt.Errorf("rejected")
			}

			return nil, fmt.Errorf("rejected")
		},
	}

	privateBytes, err := ioutil.ReadFile(*hostKey)
	if err != nil {
		logrus.Fatal(err)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		logrus.Fatal(err)
	}

	config.AddHostKey(private)

	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		logrus.Fatal(err)
	}

	logrus.Infof("Listening on %s", *listen)
	for {
		tcpConn, err := listener.Accept()
		tcpConn.Write([]byte(Xinjiang+ "\n"))
		if err != nil {
			logrus.Error(err)
			continue
		}

		sshConn, _, _, err := ssh.NewServerConn(tcpConn, &config)
		if err != nil {
			logrus.Error(err)
		}

		if sshConn != nil {
			sshConn.Close()
		}
		tcpConn.Close()

		/*
			go ssh.DiscardRequests(reqs)
			go handleChannels(chans)
		*/
	}
}

func handleChannels(chans <-chan ssh.NewChannel) {
	for newChannel := range chans {
		go handleChannel(newChannel)
	}
}

func handleChannel(newChannel ssh.NewChannel) {
	if t := newChannel.ChannelType(); t != "session" {
		newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
		return

	}

	// At this point, we have the opportunity to reject the client's
	// request for another logical connection
	connection, requests, err := newChannel.Accept()
	if err != nil {
		log.Printf("Could not accept channel (%s)", err)
		return

	}
	/*
		// Fire up bash for this session
		bash := exec.Command("bash")

		// Prepare teardown function
		close := func() {
			connection.Close()
			_, err := bash.Process.Wait()
			if err != nil {
				log.Printf("Failed to exit bash (%s)", err)

			}
			log.Printf("Session closed")

		}

		// Allocate a terminal for this channel
		log.Print("Creating pty...")
		bashf, err := pty.Start(bash)
		if err != nil {
			log.Printf("Could not start pty (%s)", err)
			close()
			return

		}
	*/
	//pipe session to bash and visa-versa
	//var once sync.Once
	go func() {
		//io.Copy(connection, bashf)
		//once.Do(close)

		scanner := bufio.NewScanner(connection)
		for scanner.Scan() {
			logrus.Infof("> %s", scanner.Text())
		}

		connection.Close()
	}()
	go func() {
		//io.Copy(bashf, connection)
		//once.Do(close)
	}()

	// Sessions have out-of-band requests such as "shell", "pty-req" and "env"
	go func() {
		for req := range requests {
			switch req.Type {
			case "shell":
				// We only accept the default shell
				// (i.e. no command in the Payload)
				if len(req.Payload) == 0 {
					req.Reply(true, nil)

				}
				/*
					case "pty-req":
						termLen := req.Payload[3]
						w, h := parseDims(req.Payload[termLen+4:])
						SetWinsize(bashf.Fd(), w, h)
						// Responding true (OK) here will let the client
						// know we have a pty ready for input
						req.Reply(true, nil)
					case "window-change":
						w, h := parseDims(req.Payload)
						SetWinsize(bashf.Fd(), w, h)
				*/
			}

		}

	}()
}

// parseDims extracts terminal dimensions (width x height) from the provided buffer.
func parseDims(b []byte) (uint32, uint32) {
	w := binary.BigEndian.Uint32(b)
	h := binary.BigEndian.Uint32(b[4:])
	return w, h

}

// ======================

// Winsize stores the Height and Width of a terminal.
type Winsize struct {
	Height uint16
	Width  uint16
	x      uint16 // unused
	y      uint16 // unused

}

// SetWinsize sets the size of the given pty.
func SetWinsize(fd uintptr, w, h uint32) {
	ws := &Winsize{Width: uint16(w), Height: uint16(h)}
	syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TIOCSWINSZ), uintptr(unsafe.Pointer(ws)))

}
