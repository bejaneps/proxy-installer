## Building Requirements

### Windows
----------------------------------------------------------

* [Go](https://golang.org/) -  main dependency of builder
* Visual Studio Community 2019
    - Select **Desktop development with C++**
    - Additionally select *MSVC v140 - VS 2015 C++ build tools (v14.00)*
* [Windows 8.1 SDK](https://developer.microsoft.com/en-us/windows/downloads/sdk-archive)

### Linux
----------------------------------------------------------
* [Go](https://golang.org/) -  main dependency of builder

----------------------------------------------------------

## Building installer

### RCA
    1. Run build script build.bat as an **administrator**
    2. Run build\installer.exe rca --help to see all available flags(arguments)

### RSA
    1. Run chmod ugo+x build.sh
    2. Change terminal to root (sudo -s)
    3. Start build script: source build.sh
    4. Exit root terminal (exit)
    5. Run installer rsa --help in build directory to see all available flags(arguments)
    6. (Optional) After building rsa, you can start it as a service, running an rsa_start.sh script as an **administrator** in configs folder
    7. (NOTE) You have to change $HOME in rsa.service for it to work ($HOME should be changed to your home path, ex: /home/someuser)

## Building binaries
----------------------------------------------------------

### RCA & RSA
    1. Change your folder to frp
    2. For RCA run:
        go build -o rca.exe .\cmd\frpc
    3. FOR RSA run:
        go build -o rsa .\cmd\frps


----------------------------------------------------------

## Installation
----------------------------------------------------------

### Windows

Default installation directory: "C:\Program Files\ServiceTree"

Besides for RCA Client itself it also installs:

* VNC Server (servicetree-rc.exe)

    It is the fork of UltraVNC server. For more details see developers guide.

* OpenSSH Server

    Configured to listen on 127.0.0.1:5960, so it is inaccessible without tunelling.

* setpasswd.exe

    Required to set/change VNC Server passwords as they are obfuscated in INI file.

RCA Client installer accepts set of flags to adjust configuration during installation. For full list of available options run `installer.exe --help`.

Following options are mandatory, if any of them is omitted installation will fail:

    --vnc-password PASS
        full access password for VNC Server

    --username
        used for rca authentication

    --password
        used for rca authentication

    --auth-url
        url to authentication server (connection)

    --dis-url
        url to authentication server (disconnect)

To add authorized key use `--ssh-trust-key path_to_key.pub|url_to_key.pub` during installation or later add file content to *C:/ProgramData/ServiceTree/authorized_keys*.

### Linux

Installation directory: $HOME/ServiceTree

Similar to rca, you can check available parameters using `installer --help` command

## Uninstall
----------------------------------------------------------

To uninstall **rca** run `clean.bat` script with **administrator** privileges

It will remove all build files by Microsoft Visual Studio, stop all services created by installer and delete root folder of ServiceTree

To uninstall **rca** run `clean.sh` script with **administrator** privileges

It will remove ServiceTree root folder, and also systemd service created by it

## Usage
----------------------------------------------------------

Example of running installer.exe for rca:
```
installer.exe rca -a https://example.com/Connect -d https://example.com/Disconnect -p srqwr -u paul -s 127.0.0.2 -r 6161 -l -t 124rqw --vnc-password qwertyuiop --vnc-password-2 poiuytrewq --vnc-query-accept --vnc-query-if-no-logon --vnc-query-timeout 25 --ssh-trust-key C:\ProgramData\ssh\keys.pub
```

Example of getting info about available parameters:
```
installer.exe --help
installer.exe rca --help
installer.exe rsa --help
```

**NOTE:** value for parameter `--ssh-trust-key` can be url to download file as well