# Windows guide

## Run demo on Windows

Use the README quick start. All detector logic, training and dashboard work with Windows Python and NumPy. The included model is ready to run. This is the easiest presentation mode.

## Run real telemetry from a Windows laptop

1. Create an Ubuntu 24.04 VM in VirtualBox, VMware or Hyper-V. Allocate around 4 CPUs / 4–8 GB RAM if your laptop allows it.
2. Copy/extract this project inside Ubuntu.
3. Install Docker **inside that Ubuntu VM** and the BCC prerequisites in `LINUX_SETUP.md`.
4. Start Linux containers in the VM. Run the server as a normal user and collector with sudo on that same VM.
5. Open `http://127.0.0.1:8080` using the VM's browser.

Keep the service loopback-only. To view it from the Windows browser, install OpenSSH Server in Ubuntu, enable SSH and use a port-forward:

```powershell
ssh -L 8080:127.0.0.1:8080 YOUR_UBUNTU_USER@YOUR_VM_IP
```

Leave SSH running and open `http://127.0.0.1:8080` on Windows. Use the token from the Ubuntu server when acknowledging alerts. Hypervisor networking must make the VM's SSH port reachable; for VirtualBox NAT, configure a host-to-guest SSH port forward and use `ssh -p HOST_SSH_PORT -L 8080:127.0.0.1:8080 USER@127.0.0.1`.

## WSL2

A dedicated Ubuntu VM is the documented live path. WSL2 kernel/header/BCC support varies. Docker Desktop may host containers in another Linux VM/distribution; a collector in your Ubuntu WSL distribution may not observe that host. This project does not claim or test WSL2 live support.

## Troubleshooting demo

- `py` not found: install Python and reopen the terminal, or replace `py -3` with your Python executable.
- NumPy install failed: use supported Python 3.10+ and check internet connectivity.
- Port already in use: run `python -m aegis.server --port 8081` and open port 8081.
- 401 on a button: enter your server's action token. Default demo value is `demo-local-token`.
- Wait for one five-second window before expecting container cards or alerts.
- Synthetic normal windows can occasionally alert; statistical thresholds have nonzero false positives.
