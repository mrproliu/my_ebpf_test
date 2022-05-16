package main

import (
	"bufio"
	"bytes"
	"embed"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"strings"
)

//go:embed *
var assets embed.FS

//
func asset(file string) ([]byte, error) {
	return assets.ReadFile(filepath.ToSlash(file))
}

//
//func assetDir(dir string) ([]fs.DirEntry, error) {
//	return assets.ReadDir(filepath.ToSlash(dir))
//}

func findKernelBTF() (io.ReaderAt, error) {
	_, err := os.Stat("/sys/kernel/btf/vmlinux")
	if err == nil {
		return nil, nil
	}
	distributution, version, err := getDistributionAndVersion()
	if err != nil {
		return nil, err
	}
	u := unix.Utsname{}
	err = unix.Uname(&u)
	if err != nil {
		return nil, err
	}
	btfPath := fmt.Sprintf("btf/%s/%s/x86_64/%s.btf", distributution, version, charsToString(u.Release))
	fmt.Printf("trying to load btf path: %s\n", btfPath)
	data, err := asset(btfPath)
	if err != nil {
		return nil, err
	}

	return bytes.NewReader(data), nil
}

func getDistributionAndVersion() (string, string, error) {
	file, err := os.Open("/etc/lsb-release")
	if err != nil {
		return "", "", err
	}
	scanner := bufio.NewScanner(file)
	var distrib, release string
	for scanner.Scan() {
		// example fields: cgroup2 /sys/fs/cgroup/unified cgroup2 rw,nosuid,nodev,noexec,relatime 0 0
		fields := strings.Split(scanner.Text(), "=")
		if len(fields) != 2 {
			continue
		}
		if fields[0] == "DISTRIB_ID" {
			distrib = strings.ToLower(fields[1])
		} else if fields[0] == "DISTRIB_RELEASE" {
			release = strings.ToLower(fields[1])
		}
	}
	fmt.Printf("dis: %s, release: %s\n", distrib, release)
	return distrib, release, nil
}

func getOSUnamer() (*UnameInfo, error) {
	u := unix.Utsname{}
	e := unix.Uname(&u)
	if e != nil {
		return nil, e
	}
	ui := UnameInfo{}
	ui.SysName = charsToString(u.Sysname)
	ui.Nodename = charsToString(u.Nodename)
	ui.Release = charsToString(u.Release)
	ui.Version = charsToString(u.Version)
	ui.Machine = charsToString(u.Machine)
	ui.Domainname = charsToString(u.Domainname)

	return &ui, nil
}

func charsToString(ca [65]byte) string {
	s := make([]byte, len(ca))
	var lens int
	for ; lens < len(ca); lens++ {
		if ca[lens] == 0 {
			break
		}
		s[lens] = uint8(ca[lens])
	}
	return string(s[0:lens])
}

type UnameInfo struct {
	SysName    string
	Nodename   string
	Release    string
	Version    string
	Machine    string
	Domainname string
}
