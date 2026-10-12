// Package datadir decides where the server keeps its database when --db is not given.
//
// A database that silently lands in whatever folder the program was started from loses its
// history as soon as someone starts it from elsewhere. So, in order:
//
//  1. --db, when given;
//  2. the CIPHERHORIZON_DB environment variable;
//  3. a cipherhorizon.db already in the working directory (where versions before 0.1.0 put it),
//     so an upgrade never appears to lose data;
//  4. the operating system's per-user data folder:
//     Windows  %LOCALAPPDATA%\CipherHorizon\cipherhorizon.db
//     macOS    ~/Library/Application Support/CipherHorizon/cipherhorizon.db
//     Linux    $XDG_DATA_HOME/cipherhorizon/cipherhorizon.db (~/.local/share/cipherhorizon/...)
//
// Services and containers name the path explicitly (/var/lib/cipherhorizon, /data,
// %ProgramData%\CipherHorizon), so they never depend on this.
package datadir

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// File is the database's file name.
const File = "cipherhorizon.db"

// EnvVar names the environment variable that overrides the default location.
const EnvVar = "CIPHERHORIZON_DB"

// Source says which rule chose the path.
type Source int

// The rules, in the order they are tried.
const (
	FromFlag Source = iota
	FromEnv
	FromWorkingDir
	FromDefault
)

// Resolve returns the database path for a --db value (empty when the flag was not given).
// For FromDefault it also creates the folder, readable by its owner only.
func Resolve(flagValue string) (string, Source, error) {
	home, _ := os.UserHomeDir()
	path, src, err := resolve(flagValue, os.Getenv, runtime.GOOS, home, exists)
	if err != nil || src != FromDefault {
		return path, src, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", src, err
	}
	return path, src, nil
}

// DefaultPath is the per-user location, without creating anything (for help text).
func DefaultPath() string {
	home, _ := os.UserHomeDir()
	p, err := defaultPath(os.Getenv, runtime.GOOS, home)
	if err != nil {
		return File
	}
	return p
}

func resolve(flagValue string, getenv func(string) string, goos, home string, exists func(string) bool) (string, Source, error) {
	switch {
	case flagValue != "":
		return flagValue, FromFlag, nil
	case getenv(EnvVar) != "":
		return getenv(EnvVar), FromEnv, nil
	case exists(File):
		return File, FromWorkingDir, nil
	}
	p, err := defaultPath(getenv, goos, home)
	return p, FromDefault, err
}

func defaultPath(getenv func(string) string, goos, home string) (string, error) {
	var dir string
	switch goos {
	case "windows":
		base := getenv("LOCALAPPDATA")
		if base == "" && home != "" {
			base = filepath.Join(home, "AppData", "Local")
		}
		if base != "" {
			dir = filepath.Join(base, "CipherHorizon")
		}
	case "darwin":
		if home != "" {
			dir = filepath.Join(home, "Library", "Application Support", "CipherHorizon")
		}
	default:
		base := getenv("XDG_DATA_HOME")
		if !strings.HasPrefix(base, "/") { // the XDG spec: a relative value is invalid and ignored
			base = ""
		}
		if base == "" && home != "" {
			base = filepath.Join(home, ".local", "share")
		}
		if base != "" {
			dir = filepath.Join(base, "cipherhorizon")
		}
	}
	if dir == "" {
		return "", errors.New("no home directory to keep the database in; name a file with --db or " + EnvVar)
	}
	return filepath.Join(dir, File), nil
}

func exists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}
