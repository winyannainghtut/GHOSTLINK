// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

//go:build linux && (amd64 || arm64)

package main

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

// becomeAccount runs before anything else. Docker gives a container started as another user no
// capabilities at all (it sets no ambient ones), so the host script starts this one as root
// with only SETUID, SETGID, SETPCAP and NET_BIND_SERVICE, and names the server account in
// GHOSTLINK_RUN_AS. The server then removes every capability but NET_BIND_SERVICE from its
// bounding set, becomes that account keeping NET_BIND_SERVICE as an ambient capability, and
// starts again as it. From then on it is not root and holds one capability: the one that lets it
// listen on ports below 1024, such as 443. no-new-privileges stays on throughout. A server
// started without GHOSTLINK_RUN_AS, as root or as any other user, runs as it is.
func becomeAccount() error {
	spec, named := os.LookupEnv(runAsVariable)
	if os.Getuid() != 0 && os.Geteuid() != 0 {
		if !named {
			return nil
		}
		// After the start again: check that the change of account took.
		uid, gid, err := parseRunAs(spec)
		if err != nil {
			return err
		}
		if os.Getuid() != uid || os.Geteuid() != uid || os.Getgid() != gid || os.Getegid() != gid {
			return fmt.Errorf("runs as %d:%d, not as %s=%s", os.Geteuid(), os.Getegid(), runAsVariable, spec)
		}
		return nil
	}
	if !named {
		// Root with no account to become (a server run by hand, or by the mesh end-to-end test):
		// it runs as it is, as before. The host script always names the account.
		return nil
	}
	uid, gid, err := parseRunAs(spec)
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	// Credentials and capabilities belong to a thread: everything below changes only this one,
	// and execve, called from it, starts the new program with them (the other threads end).
	runtime.LockOSThread()
	for c := uintptr(0); c < 64; c++ {
		if c == unix.CAP_NET_BIND_SERVICE {
			continue
		}
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, c, 0, 0, 0); err != nil {
			if errors.Is(err, unix.EINVAL) {
				break // past the last capability this kernel knows
			}
			return fmt.Errorf("could not drop capability %d: %w (the container needs --cap-add SETPCAP)", c, err)
		}
	}
	// Keeps the permitted set through the change of account; the effective set is cleared.
	if err := unix.Prctl(unix.PR_SET_KEEPCAPS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("could not keep capabilities: %w", err)
	}
	if _, _, e := unix.RawSyscall(unix.SYS_SETGROUPS, 0, 0, 0); e != 0 {
		return fmt.Errorf("could not drop the supplementary groups: %w (the container needs --cap-add SETGID)", e)
	}
	if _, _, e := unix.RawSyscall(unix.SYS_SETRESGID, uintptr(gid), uintptr(gid), uintptr(gid)); e != 0 {
		return fmt.Errorf("could not become group %d: %w (the container needs --cap-add SETGID)", gid, e)
	}
	if _, _, e := unix.RawSyscall(unix.SYS_SETRESUID, uintptr(uid), uintptr(uid), uintptr(uid)); e != 0 {
		return fmt.Errorf("could not become user %d: %w (the container needs --cap-add SETUID)", uid, e)
	}
	bind := uint32(1) << unix.CAP_NET_BIND_SERVICE
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{{Effective: bind, Permitted: bind, Inheritable: bind}}
	if err := unix.Capset(&header, &data[0]); err != nil {
		return fmt.Errorf("could not keep NET_BIND_SERVICE: %w (the container needs --cap-add NET_BIND_SERVICE)", err)
	}
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_RAISE, unix.CAP_NET_BIND_SERVICE, 0, 0); err != nil {
		return fmt.Errorf("could not pass NET_BIND_SERVICE on: %w", err)
	}
	return syscall.Exec(exe, os.Args, os.Environ())
}
