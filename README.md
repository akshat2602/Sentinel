# Sentinel

Sentinel is a tool developed to act as an additional layer of security for TCP services. It serves as a "jump" proxy, adding an extra layer of encryption to connections towards TCP services. This README provides guidance on how to set up Sentinel and get it running.

## Setup Instructions

1. **Install Go**: Install the latest version of Go using instructions at [Official Golang Website](https://go.dev/doc/install)

2. **Navigate to the Directory**: Move into the cloned repository directory.

    ```bash
    cd Sentinel
    ```

3. **Install dependencies**: Install the dependencies for this program.(golang.org/x/crypto)

    ```bash
    go mod tidy
    ```

4. **Create Password File**: Create a password file containing the passphrase for encryption. This file will be used as an argument when running Sentinel.

    ```bash
    echo "YourPassphraseHere" > pwdfile
    ```

    Replace "YourPassphraseHere" with the desired passphrase.


## Running Sentinel

### Reverse Proxy Mode 
To run Sentinel in forward proxy mode, use the following command:
```bash
go run sentinel.go -l listenport -k pwdfile destination port
```
- **listenport**: Listen port for reverse-proxy mode.
- **pwdfile**: Path to the ASCII text passphrase file.
- **destination**: IP address or hostname of the target service.
- **port**: Port number of the target service.

Example command:
```bash
go run sentinel.go -l 2222 -k pwdfile localhost 22
```

### Forward Proxy Mode
To run Sentinel in reverse proxy mode, use the following command:

```bash
ssh -o "ProxyCommand go run sentinel.go -k pwdfile destination port" kali@localhost
```
- **pwdfile**: Path to the ASCII text passphrase file.
- **destination**: IP address or hostname of the target service.
- **port**: Port number of the target service.

Example command:
```bash
ssh -o "ProxyCommand go run sentinel.go -k pwdfile localhost 2222" kali@localhost
```