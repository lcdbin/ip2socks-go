package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"golang.org/x/net/proxy"

	"github.com/lcdbin/ip2socks-go/tproxy"
)

var (
	OptionTCP       = 0x01 << 0
	OptionUDP       = 0x01 << 1
	OptionIPv4      = 0x01 << 2                                       /* enable ipv4 */
	OptionIPv6      = 0x01 << 3                                       /* enable ipv6 */
	OptionDNAT      = 0x01 << 4                                       /* use REDIRECT instead of TPROXY (for tcp) */
	OptionHFCLS     = 0x01 << 5                                       /* gracefully close the tcp connection pair */
	OptionalDefault = OptionTCP | OptionUDP | OptionIPv4 | OptionIPv6 /* default behavior */
)

type Options struct {
	ServerAddr   string
	ServerPort   uint
	authUser     string
	authPwd      string
	listenAddrv4 string
	listenAddrv6 string
	listenPort   uint
	threadNum    uint // useless for go
	noFileLimit  uint // dont know what it is
	UDPTimeout   uint
	CacheSize    uint
	BufferSize   uint
	RunAsUser    string
	Graceful     uint
	Redirect     uint // TODO: support this option
	TCPOnly      uint
	UDPOnly      uint
	IPv4Only     uint
	IPv6Only     uint
	Verbose      uint
}

var option Options

func verboseLog() bool {
	return 0 != option.Verbose
}

func parseCommandArgs() {
	flag.StringVar(&option.ServerAddr, "server-addr", "127.0.0.1", "server ip address")
	flag.UintVar(&option.ServerPort, "server-port", 9999, "server ip address port")
	flag.StringVar(&option.authUser, "auth-username", "nobody", "socks5 user name")
	flag.StringVar(&option.authPwd, "auth-password", "", "socks5 user password")
	flag.StringVar(&option.listenAddrv4, "listen-addr4", "0.0.0.0", "ip2socks ipv4 listen address")
	flag.StringVar(&option.listenAddrv6, "listen-addr6", "::", "ip2socks ipv6 listen address")
	flag.UintVar(&option.listenPort, "listen-port", 443, "ip2socks ipv4 listen port")
	flag.UintVar(&option.UDPTimeout, "udp-timeout", 0, "udp timeout")
	flag.UintVar(&option.CacheSize, "cache-size", 0, "cache size")
	flag.UintVar(&option.BufferSize, "buffer-size", 0, "buffer size")
	flag.StringVar(&option.RunAsUser, "run-user", "current user", "run as user")
	flag.UintVar(&option.Graceful, "graceful", 0, "graceful")
	flag.UintVar(&option.Redirect, "redirect", 0, "redirect")
	flag.UintVar(&option.TCPOnly, "tcp-only", 0, "tcp only")
	flag.UintVar(&option.UDPOnly, "udp-only", 0, "udp only")
	flag.UintVar(&option.IPv4Only, "ipv4-only", 0, "ipv4 only")
	flag.UintVar(&option.IPv6Only, "ipv6-only", 0, "ipv6 only")
	flag.UintVar(&option.Verbose, "verbose", 0, "server ip address")
}

func forwardStream(from net.Conn, to net.Conn, done chan<- int) {
	defer func() { done <- 1 }()
	data := make([]byte, 1024)
	for {
		n, err := from.Read(data)
		if nil != err {
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				// FIXME:
				if 0 != n {
					// panic("error but has n")
					goto hasN
				}
				log.Printf("ERROR Temporary, failed to read data from socket %s, err:%s", from.RemoteAddr().String(), err.Error())
				continue
			}

			if err == io.EOF {
				if verboseLog() {
					log.Printf("connection from %s to %s read EOF...", from.RemoteAddr().String(), to.RemoteAddr().String())
					break
				}
			}
			log.Printf("ERROR, failed to read accept, err:%s, destroy stream...", err.Error())
			break
		}

	hasN:
		if 0 != n {
			n, err = to.Write(data[:n])
			if nil != err {
				log.Printf("ERROR, failed to write to peer %s, err:%s", to.RemoteAddr().String(), err.Error())
				break
			}
			if verboseLog() {
				log.Printf("forward stream xxxx %d bytes", n)
			}
		}
	} // for

	if verboseLog() {
		log.Printf("forward tcp stream quit...")
	}
}

func udpToSocks5(ctx context.Context, data []byte, srcAddr, dstAddr *net.UDPAddr) {
	localConn, err := tproxy.DialUDP("udp", dstAddr, srcAddr)
	if err != nil {
		log.Printf("Failed to connect to original UDP source [%s]: %s", srcAddr.String(), err)
		return
	}
	defer localConn.Close()

	remoteConn, err := tproxy.DialUDP("udp", srcAddr, dstAddr)
	if err != nil {
		log.Printf("Failed to connect to original UDP destination [%s]: %s", dstAddr.String(), err)
		return
	}
	defer remoteConn.Close()

	bytesWritten, err := remoteConn.Write(data)
	if err != nil {
		log.Printf("Encountered error while writing to remote [%s]: %s", remoteConn.RemoteAddr(), err)
		return
	} else if bytesWritten < len(data) {
		log.Printf("Not all bytes [%d < %d] in buffer written to remote [%s]", bytesWritten, len(data), remoteConn.RemoteAddr())
		return
	}

	data = make([]byte, 1024)
	_ = remoteConn.SetReadDeadline(time.Now().Add(1 * time.Second)) // Add deadline to ensure it doesn't block forever
	bytesRead, err := remoteConn.Read(data)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			log.Printf("read udp timeout...")
			return
		}
		log.Printf("encountered error while reading from remote [%s]: %s", remoteConn.RemoteAddr(), err.Error())
		return
	}

	bytesWritten, err = localConn.Write(data)
	if err != nil {
		log.Printf("encountered error while writing to local [%s]: %s", localConn.RemoteAddr(), err)
		return
	}

	if bytesWritten < bytesRead {
		log.Printf("Not all bytes [%d < %d] in buffer written to locoal [%s]", bytesWritten, len(data), remoteConn.RemoteAddr())
		return
	}
}

func serverUDP(ctx context.Context, udpListener *net.UDPConn) {
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		default:
			// TODO: 1024 is the buffer size enough ?
			buff := make([]byte, 1024)
			n, srcAddr, dstAddr, err := tproxy.ReadFromUDP(udpListener, buff)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
					log.Printf("Temporary error while reading data: %s", netErr)
				}

				log.Fatalf("Unrecoverable error while reading data: %s", err)
				return
			}

			if verboseLog() {
				log.Printf("accept new udp connection from %s, get 'local' %s", srcAddr.String(), dstAddr.String())
			}

			go udpToSocks5(ctx, buff[:n], srcAddr, dstAddr)
			// udpToSocks5(ctx, buff[:n], srcAddr, dstAddr)
		}
	}

	if verboseLog() {
		log.Printf("udp listener quit...")
	}
	udpListener.Close()
}

func serveTCP(ctx context.Context, tcpListener net.Listener) {
loop:
	for {
		select {
		case <-ctx.Done():
			log.Printf("tcp server found context done...")
			break loop
		default:
			client, err := tcpListener.Accept()
			if nil != err {
				if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
					log.Printf("ERROR, failed to accept client connect, err:%s", err.Error())
					continue
				}
				log.Printf("ERROR, failed to call accept, err:%s, exit...", err.Error())
				break loop
			}

			if verboseLog() {
				log.Printf("accept new tcp connection from %s, get 'local' %s", client.RemoteAddr().String(), client.LocalAddr().String())
			}

			go tcpToSocks5(ctx, client)
		} // select
	} // for

	if verboseLog() {
		log.Printf("tcp listener quit...")
	}
	tcpListener.Close()
}

// a new connection comes...prepare socks5 connect and start to forward data...
func tcpToSocks5(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	// init socks5 dialer
	auth := proxy.Auth{User: option.authUser, Password: option.authPwd}
	dialer, err := proxy.SOCKS5("tcp4", fmt.Sprintf("%s:%d", option.ServerAddr, option.ServerPort), &auth, proxy.Direct)
	if nil != err {
		log.Printf("ERROR, can't get socks5 dialer, err:%s", err.Error())
		return
	}

	// Dial() connect to proxy you defined by calling SOCKS5(), and tranlate real host address to proxy server
	if verboseLog() {
		log.Printf("remote %s to local %s", conn.RemoteAddr().String(), conn.LocalAddr().String())
	}
	socks5, err := dialer.Dial("tcp", conn.LocalAddr().String())
	if nil != err {
		log.Printf("ERROR, failed to call SOCKS5 dial...err:%s", err.Error())
		return
	}
	defer socks5.Close()

	streamDone := make(chan int, 2)
	go forwardStream(conn, socks5, streamDone)
	go forwardStream(socks5, conn, streamDone)
	for {
		select {
		case <-ctx.Done():
			return
		case <-streamDone: // unnecessary to wait two forwardStream goroutines done
			return
		default:
			time.Sleep(time.Second)
		}
	}
}

func runIP2Socks5Server() error {
	// FIXME: use correct option from cmdline args
	var tcpListeners []net.Listener
	var udpListeners []*net.UDPConn

	if 0 == option.UDPOnly { // should have tcp
		if 0 == option.IPv4Only { // should have ipv6
			tcpListener6, err := tproxy.ListenTCP("tcp6", &net.TCPAddr{IP: net.ParseIP(option.listenAddrv6), Port: int(option.listenPort)})
			if nil != err {
				log.Printf("ERROR, failed to listen ipv6 tcp tproxy, err:%s", err.Error())
				return err
			}
			tcpListeners = append(tcpListeners, tcpListener6)
		}

		if 0 == option.IPv6Only {
			tcpListener4, err := tproxy.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP(option.listenAddrv4), Port: int(option.listenPort)})
			if nil != err {
				log.Printf("ERROR, failed to listen ipv4 tcp tproxy, err:%s", err.Error())
				return err
			}
			tcpListeners = append(tcpListeners, tcpListener4)
		}
	}

	if 0 == option.TCPOnly { // should have udp
		if 0 == option.IPv4Only { // should have ipv6
			udpListener6, err := tproxy.ListenUDP("udp6", &net.UDPAddr{IP: net.ParseIP(option.listenAddrv6), Port: int(option.listenPort)})
			if nil != err {
				log.Printf("ERROR, failed to listen ipv6 udp tproxy, err:%s", err.Error())
				return err
			}
			udpListeners = append(udpListeners, udpListener6)
		}

		if 0 == option.IPv6Only {
			udpListener4, err := tproxy.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(option.listenAddrv4), Port: int(option.listenPort)})
			if nil != err {
				log.Printf("ERROR, failed to listen ipv4 udp tproxy, err:%s", err.Error())
				return err
			}
			udpListeners = append(udpListeners, udpListener4)
		}
	}

	ctx := context.Background()
	for _, t := range tcpListeners {
		go serveTCP(ctx, t)
	}

	for _, u := range udpListeners {
		go serverUDP(ctx, u)
	}

	return nil
}

func logInit() *os.File {
	// If the file doesn't exist, create it, or append to the file
	f, err := os.OpenFile("ip2table.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
		return nil
	}

	log.SetFlags(log.Ldate | log.Ltime | log.Llongfile)
	log.SetOutput(f)
	return f
}

func main() {
	log.Printf("process start...")
	parseCommandArgs()
	flag.Parse()

	f := logInit()
	defer f.Close()

	err := runIP2Socks5Server()
	if nil != err {
		log.Printf("run server error, %s", err.Error())
		return
	}

	for {
		// TODO: signal to quit...
		time.Sleep(time.Second)
	}
}
