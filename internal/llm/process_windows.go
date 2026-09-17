//go:build windows

package llm

import "os/exec"

// Windows no expone Setpgid. Mantener los defaults permite compilar el
// cliente; el sidecar local se administra normalmente en Kali/Linux.
func detachProcess(cmd *exec.Cmd) {}
