package main

import (
	"golang.org/x/sys/unix"
)

////go:embed *
//var assets embed.FS
//
//func asset(file string) ([]byte, error) {
//	return assets.ReadFile(filepath.ToSlash(file))
//}
//
//func assetDir(dir string) ([]fs.DirEntry, error) {
//	return assets.ReadDir(filepath.ToSlash(dir))
//}

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
