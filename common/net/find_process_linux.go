//go:build linux && !android

package net

import (
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/common/errors"
)

func FindProcess(network, srcIP string, srcPort uint16, destIP string, destPort uint16) (PID int, Name string, AbsolutePath string, err error) {
	srcAddr, err := netip.ParseAddr(srcIP)
	if err != nil {
		return 0, "", "", errors.New("invalid source IP address: ", srcIP).Base(err)
	}
	srcAddr = srcAddr.Unmap()

	isLocal, err := IsLocal(net.IP(srcAddr.AsSlice()))
	if err != nil {
		return 0, "", "", errors.New("failed to determine if address is local: ", err)
	}
	if !isLocal {
		return 0, "", "", ErrNotLocal
	}
	if network != "tcp" && network != "udp" {
		panic("Unsupported network type for process lookup.")
	}

	targets := procNetTargets(network, srcAddr)

	var inode string
	for _, target := range targets {
		targetHexAddr := formatLinuxProcNetAddress(srcAddr, Port(srcPort), target.ipv6)

		inode, err = findInodeInFile(target.path, targetHexAddr)
		if err != nil {
			return 0, "", "", errors.New("could not search in ", target.path).Base(err)
		}
		if inode != "" {
			break
		}
	}
	if inode == "" {
		return 0, "", "", errors.New("connection for ", network, " ", srcIP, ":", srcPort, " not found")
	}

	pidStr, err := findPidByInode(inode)
	if err != nil {
		return 0, "", "", errors.New("could not find PID for inode ", inode, ": ", err)
	}
	if pidStr == "" {
		return 0, "", "", errors.New("no process found for inode ", inode)
	}

	absPath, err := getAbsPath(pidStr)
	if err != nil {
		return 0, "", "", errors.New("could not get process name for PID ", pidStr, ":", err)
	}

	nameSplit := strings.Split(absPath, "/")
	procName := nameSplit[len(nameSplit)-1]

	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return 0, "", "", errors.New("failed to parse PID: ", err)
	}

	return pid, procName, absPath, nil
}

type procNetTarget struct {
	path string
	ipv6 bool
}

func procNetTargets(network string, addr netip.Addr) []procNetTarget {
	prefix := "/proc/net/" + network
	if addr.Is4() {
		return []procNetTarget{
			{path: prefix, ipv6: false},
			{path: prefix + "6", ipv6: true},
		}
	}
	return []procNetTarget{{path: prefix + "6", ipv6: true}}
}

func formatLinuxProcNetAddress(addr netip.Addr, port Port, ipv6 bool) string {
	var raw []byte
	if ipv6 {
		addr16 := addr.As16()
		raw = addr16[:]
	} else {
		addr4 := addr.As4()
		raw = addr4[:]
	}

	var builder strings.Builder
	for i := 0; i < len(raw); i += 4 {
		fmt.Fprintf(&builder, "%02X%02X%02X%02X", raw[i+3], raw[i+2], raw[i+1], raw[i])
	}
	fmt.Fprintf(&builder, ":%04X", uint16(port))
	return builder.String()
}

func findInodeInFile(filePath, targetHexAddr string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)

		if len(fields) < 10 {
			continue
		}

		localAddress := fields[1]
		if localAddress == targetHexAddr {
			inode := fields[9]
			return inode, nil
		}
	}

	return "", scanner.Err()
}

func findPidByInode(inode string) (string, error) {
	procDir, err := os.ReadDir("/proc")
	if err != nil {
		return "", err
	}

	targetLink := "socket:[" + inode + "]"

	for _, entry := range procDir {
		if !entry.IsDir() {
			continue
		}
		pid := entry.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}

		fdPath := fmt.Sprintf("/proc/%s/fd", pid)
		fdDir, err := os.ReadDir(fdPath)
		if err != nil {
			continue
		}

		for _, fdEntry := range fdDir {
			linkPath := fmt.Sprintf("%s/%s", fdPath, fdEntry.Name())
			linkTarget, err := os.Readlink(linkPath)
			if err != nil {
				continue
			}
			if linkTarget == targetLink {
				return pid, nil
			}
		}
	}
	return "", nil
}

func getAbsPath(pid string) (string, error) {
	path := fmt.Sprintf("/proc/%s/exe", pid)
	return os.Readlink(path)
}
