//go:build windows

package winsvc

import (
	"context"
	"errors"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// Errors a caller explains to the user.
var (
	ErrNeedAdmin    = errors.New("this needs an administrator: open PowerShell with \"Run as administrator\" and try again")
	ErrNotInstalled = errors.New("the service is not installed")
	ErrExists       = errors.New("the service is already installed")
	ErrStopped      = errors.New("the service stopped right after starting")
)

// Config describes a service to install.
type Config struct {
	Name, Display, Description string
	Exe                        string   // the program the service manager starts
	Args                       []string // its arguments
	Account                    string   // e.g. `NT AUTHORITY\LocalService`
}

func connect() (*mgr.Mgr, error) {
	m, err := mgr.Connect()
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return nil, ErrNeedAdmin
	}
	return m, err
}

func open(name string) (*mgr.Mgr, *mgr.Service, error) {
	m, err := connect()
	if err != nil {
		return nil, nil, err
	}
	s, err := m.OpenService(name)
	if err != nil {
		_ = m.Disconnect()
		return nil, nil, ErrNotInstalled
	}
	return m, s, nil
}

// Install registers the service: automatic (delayed) start, restart after a failure (5 s, 30 s,
// then every minute; the count resets after a day).
func Install(c Config) error {
	m, err := connect()
	if err != nil {
		return err
	}
	defer m.Disconnect() //nolint:errcheck // nothing to do on failure
	if s, err := m.OpenService(c.Name); err == nil {
		_ = s.Close()
		return ErrExists
	}
	s, err := m.CreateService(c.Name, c.Exe, mgr.Config{
		DisplayName:      c.Display,
		Description:      c.Description,
		StartType:        mgr.StartAutomatic,
		DelayedAutoStart: true,
		ServiceStartName: c.Account,
		ErrorControl:     mgr.ErrorNormal,
	}, c.Args...)
	if err != nil {
		return err
	}
	defer s.Close() //nolint:errcheck // nothing to do on failure
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: time.Minute},
	}, uint32((24 * time.Hour).Seconds()))
	return s.SetRecoveryActionsOnNonCrashFailures(true)
}

// Start starts the service and waits for it to be running, and still running a moment later
// (a bad option fails a second or two after "running").
func Start(name string, limit time.Duration) error {
	m, s, err := open(name)
	if err != nil {
		return err
	}
	defer m.Disconnect() //nolint:errcheck // nothing to do on failure
	defer s.Close()      //nolint:errcheck // nothing to do on failure
	if err := s.Start(); err != nil {
		return err
	}
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		st, err := s.Query()
		if err != nil {
			return err
		}
		switch st.State {
		case svc.Running:
			time.Sleep(2 * time.Second)
			if st, err = s.Query(); err == nil && st.State == svc.Running {
				return nil
			}
			return ErrStopped
		case svc.Stopped:
			return ErrStopped
		}
		time.Sleep(300 * time.Millisecond)
	}
	return ErrStopped
}

// Stop asks the service to stop and waits up to limit for it.
func Stop(name string, limit time.Duration) error {
	m, s, err := open(name)
	if err != nil {
		return err
	}
	defer m.Disconnect() //nolint:errcheck // nothing to do on failure
	defer s.Close()      //nolint:errcheck // nothing to do on failure
	return stop(s, limit)
}

func stop(s *mgr.Service, limit time.Duration) error {
	st, err := s.Control(svc.Stop)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
			return nil
		}
		return err
	}
	for deadline := time.Now().Add(limit); st.State != svc.Stopped && time.Now().Before(deadline); {
		time.Sleep(200 * time.Millisecond)
		if st, err = s.Query(); err != nil {
			return err
		}
	}
	return nil
}

// Remove stops the service (if running) and deletes it.
func Remove(name string) error {
	m, s, err := open(name)
	if err != nil {
		return err
	}
	defer m.Disconnect() //nolint:errcheck // nothing to do on failure
	_ = stop(s, 10*time.Second)
	err = s.Delete()
	_ = s.Close()
	return err
}

// Status is what Query reports.
type Status struct {
	State   string // running, stopped, starting, stopping, …
	Running bool
	Command string // the command line the service manager runs
}

// Query reads the service's state and command line with the least access, so it needs no
// administrator.
func Query(name string) (Status, error) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return Status{}, err
	}
	defer windows.CloseServiceHandle(scm) //nolint:errcheck // nothing to do on failure
	h, err := windows.OpenService(scm, windows.StringToUTF16Ptr(name), windows.SERVICE_QUERY_STATUS|windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		return Status{}, ErrNotInstalled
	}
	s := &mgr.Service{Name: name, Handle: h}
	defer s.Close() //nolint:errcheck // nothing to do on failure
	st, err := s.Query()
	if err != nil {
		return Status{}, err
	}
	cfg, _ := s.Config()
	state := map[svc.State]string{svc.Stopped: "stopped", svc.StartPending: "starting", svc.StopPending: "stopping",
		svc.Running: "running", svc.ContinuePending: "resuming", svc.PausePending: "pausing", svc.Paused: "paused"}[st.State]
	return Status{State: state, Running: st.State == svc.Running, Command: cfg.BinaryPathName}, nil
}

// IsService reports whether the service manager started this process.
func IsService() (bool, error) { return svc.IsWindowsService() }

// Run hands the process to the service manager. serve runs until its context is cancelled
// (Windows asked the service to stop or the machine is shutting down) or it returns by itself;
// a non-zero result is reported as a failure, so the recovery actions restart the service.
func Run(name string, serve func(context.Context) int) (int, error) {
	h := &handler{serve: serve}
	err := svc.Run(name, h)
	return h.code, err
}

type handler struct {
	serve func(context.Context) int
	code  int
}

// Execute is called by the service manager (svc.Handler).
func (h *handler) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan int, 1)
	go func() { done <- h.serve(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case code := <-done: // ended by itself: a bad option or a fatal error, already logged
			h.code = code
			if code != 0 {
				return true, 1 // service-specific failure: the recovery actions apply
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending, WaitHint: 20000}
				cancel()
				select {
				case h.code = <-done:
				case <-time.After(20 * time.Second):
				}
				return false, 0
			}
		}
	}
}

// LockDown replaces dir's permissions with the protected DACL in sddl (inherited below it).
func LockDown(dir, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}
