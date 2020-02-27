package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"scanport/scan"
	"time"
)

var (
	ip      = flag.String("ip", "127.0.0.1", "IP地址或者域名")
	port    = flag.String("p", "80-1000", "端口号范围，例如80,81,88-1000")
	path    = flag.String("path", "log", "日志地址")
	timeout = flag.Int("t", 200, "超时时间(毫秒)")
	process = flag.Int("n", 100, "并发数")
	help    = flag.Bool("h", false, "帮助信息")
)

func main() {
	flag.Parse()

	if true == *help {
		flag.PrintDefaults()
		return
	}

	startTime := time.Now()
	fmt.Printf("========== Start %v ip:%v,port:%v ==========\n", time.Now().Format("2006-01-02 15:04:05"), *ip, *port)

	err := scan.MkDir(*path)
	if err != nil {
		//tood
	}

	scanIP := scan.NewIPScan(*timeout, *process, scan.IsDebug(true))

	ips, err := scanIP.GetAllIP(*ip)
	if err != nil {
		fmt.Println(err)
		return
	}

	fileName := filepath.Join(*path, *ip+"_port.txt")
	for i := 0; i < len(ips); i++ {
		ports := scanIP.GetIPOpenPort(ips[i], *port)
		if len(ports) > 0 {
			f, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
			if err != nil {
				if err := f.Close(); err != nil {
					fmt.Println(err)
				}
				// todo  deal error
				continue
			}

			str := fmt.Sprintf("%v ip:%v, 开放端口:%v \n", time.Now().Format("2006-01-02 15:04:05"), ips[i], ports)
			if _, err := f.WriteString(str); err != nil {
				fmt.Println(err)
			}
		}
	}

	fmt.Printf("========== End %v 执行时长：%.2fs  ==========\n", time.Now().Format("2006-01-02 15:04:05"), time.Since(startTime).Seconds())
}
