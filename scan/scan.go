package scan

import (
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

//IPScan 扫描IP
type IPScan struct {
	debug   bool
	timeout int
	process int
}

//NewIPScan ...
func NewIPScan(timeout, process int, optFunc ...ModifyOptFunc) *IPScan {
	//定义默认参数
	option := Option{
		debug: false,
	}

	//调用函数修改默认参数
	for _, fun := range optFunc {
		fun(&option)
	}

	return &IPScan{
		debug:   option.debug,
		timeout: timeout,
		process: process,
	}
}

//GetIPOpenPort ...
func (s *IPScan) GetIPOpenPort(ip, port string) []int {
	var (
		total          int
		coroutineCount int
		num            int
		openPorts      []int
		mutex          sync.Mutex
	)
	ports, _ := s.getAllPort(port)
	total = len(ports)
	if total < s.process {
		coroutineCount = total
	} else {
		coroutineCount = s.process
	}

	num = int(math.Ceil(float64(total) / float64(coroutineCount)))

	s.sendLog(fmt.Sprintf("%v [%v]需要扫描端口总数:%v个， 总协程：%v个，每个协程处理%v个， 超时时间:%v毫秒", time.Now().Format("2006-01-02 15:04:05"), ip, total, coroutineCount, num, s.timeout))
	start := time.Now()
	all := map[int][]int{}
	// todo 这里的分配方法可以改善
	for i := 1; i <= coroutineCount; i++ {
		for j := 0; j < num; j++ {
			tmp := (i-1)*num + j
			if tmp < total {
				all[i] = append(all[i], ports[tmp])
			}
		}
	}

	wg := sync.WaitGroup{}
	for k, v := range all {
		wg.Add(1)
		go func(value []int, key int) {
			defer wg.Done()

			var tmpPorts []int
			for i := 0; i < len(value); i++ {
				opened := s.isOpen(ip, value[i])
				if opened {
					tmpPorts = append(tmpPorts, value[i])
				}
			}
			mutex.Lock()
			openPorts = append(openPorts, tmpPorts...)
			mutex.Unlock()
			if len(tmpPorts) > 0 {
				s.sendLog(fmt.Sprintf("%v [%v]协程%v 执行完成，时长： %.3fs，开放端口： %v", time.Now().Format("2006-01-02 15:04:05"), ip, key, time.Since(start).Seconds(), tmpPorts))
			}
		}(v, k)
	}

	wg.Wait()
	s.sendLog(fmt.Sprintf("%v [%v]扫描结束，执行时长%.3fs , 所有开放的端口:%v", time.Now().Format("2006-01-02 15:04:05"), ip, time.Since(start).Seconds(), openPorts))
	return openPorts
}

//GetAllIP 获取所有IP
func (s *IPScan) GetAllIP(ip string) ([]string, error) {
	var (
		ips []string
	)

	ipTmp := strings.Split(ip, "-")
	firstIP, err := net.ResolveIPAddr("ip", ipTmp[0])
	if err != nil {
		return ips, errors.New(ipTmp[0] + "域名解析失败" + err.Error())
	}
	if net.ParseIP(firstIP.String()) == nil {
		return ips, errors.New(ipTmp[0] + " ip地址有误~")
	}
	//域名转化成ip再塞回去
	ipTmp[0] = firstIP.String()
	ips = append(ips, ipTmp[0]) //最少有一个ip地址

	if len(ipTmp) == 2 {
		//以切割第一段ip取到最后一位
		ipTmp2 := strings.Split(ipTmp[0], ".")
		startIP, _ := strconv.Atoi(ipTmp2[3])
		endIP, err := strconv.Atoi(ipTmp[1])
		if err != nil || endIP < startIP {
			endIP = startIP
		}
		if endIP > 255 {
			endIP = 255
		}
		totalIP := endIP - startIP + 1
		for i := 1; i < totalIP; i++ {
			ips = append(ips, fmt.Sprintf("%s.%s.%s.%d", ipTmp2[0], ipTmp2[1], ipTmp2[2], startIP+i))
		}
	}
	return ips, nil
}

func (s *IPScan) getAllPort(port string) ([]int, error) {
	if "" == port {
		return []int{}, errors.New("不存在端口。")
	}

	ret := make([]int, 0)
	ports := strings.Split(strings.Trim(port, ","), ",")
	for _, val := range ports {
		portArr := strings.Split(strings.Trim(val, "-"), "-")
		startPort, err := s.filterPort(portArr[0])
		if err != nil {
			log.Println(err)
			continue
		}

		//单个端口或者范围端口的第一个
		ret = append(ret, startPort)
		if len(portArr) > 1 {
			endPort, err := s.filterPort(portArr[1])
			if err != nil {
				log.Printf("范围端口[%s]尾端点不合法(起始端点已加入)", val)
				continue
			}
			if endPort > startPort {
				for i := 0; i <= endPort-startPort; i++ {
					// todo 考虑直接生成个切片，再append
					ret = append(ret, startPort+i) //这里会有重复
				}
			}
		}
	}

	ret = s.arrayUnique(ret)

	return ret, nil
}

func (s *IPScan) filterPort(sPort string) (int, error) {
	port, err := strconv.Atoi(sPort)
	if err != nil {
		return 0, err
	}

	if port < 1 || port > 65535 {
		return 0, errors.New("端口号范围超出")
	}

	return port, nil
}

//arrayUnique 切片去重
func (s *IPScan) arrayUnique(arr []int) []int {
	var newArr []int
	var repeat bool

	for i := 0; i < len(arr); i++ {
		repeat = false
		for j := i + 1; j < len(arr); j++ {
			if arr[i] == arr[j] {
				repeat = true
				break
			}
		}
		if !repeat {
			newArr = append(newArr, arr[i])
		}
	}

	return newArr
}

//isOpen 查看端口号是否打开
func (s *IPScan) isOpen(ip string, port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), time.Millisecond*time.Duration(s.timeout))
	if err != nil {
		if strings.Contains(err.Error(), "too many open files") {
			fmt.Println("连接数超出系统限制！ ", err.Error())
			os.Exit(1)
		}
		return false
	}

	// todo deal return value?
	conn.Close()
	return true
}

func (s *IPScan) sendLog(str string) {
	if s.debug {
		fmt.Println(str)
	}
}

//Option 用于实现默认参数
type Option struct {
	debug bool
}

//ModifyOptFunc 修改默认参数的函数类型
type ModifyOptFunc func(opt *Option)

//IsDebug 实际修改默认参数的函数
func IsDebug(debug bool) ModifyOptFunc {
	return func(opt *Option) {
		opt.debug = debug
	}
}

//MkDir 创建文件夹
func MkDir(path string) error {
	f, err := os.Stat(path)
	if err != nil || false == f.IsDir() {
		if err := os.Mkdir(path, os.ModePerm); err != nil {
			return err
		}
	} else {
		return errors.New("目录[" + path + "]已经存在。")
	}

	return nil
}
