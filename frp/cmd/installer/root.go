package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/go-ini/ini"
	"github.com/spf13/cobra"
)

const (
	pathToMSBUILD = "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Community\\MSBuild\\Current\\Bin\\MSBUILD.exe"
	pathToNSIS    = "C:\\Program Files (x86)\\NSIS\\makensis.exe"
	pathToNSSM    = "C:\\Program Files\\nssm-2.24\\win64\\nssm.exe"
	pathToNASM    = "C:\\Program Files\\NASM\\nasm.exe"

	pathToServiceTreeWindows = "C:\\Program Files\\ServiceTree"
	pathToProgramFiles32     = "C:\\Program Files (x86)"
	pathToProgramFiles64     = "C:\\Program Files"
	pathToSSH                = "C:\\Windows\\System32\\OpenSSH\\sshd.exe"

	serviceTree = "ServiceTree"
)

var (
	vncPassword       string
	vncPassword2      string
	vncQueryAccept    bool
	vncQueryReject    bool
	vncQueryTimeout   string
	vncQueryIfNoLogon bool

	token       string
	sshTrustKey string

	rcaUsername   string
	rcaPassword   string
	rcaAuthURL    string
	rcaDisURL     string
	rcaServerAddr string
	rcaServerPort string
	rcaTLS        bool

	rsaBindAddr string
	rsaBindPort string

	workingDir string

	pathToServiceTreeLinux string
)

func init() {
	cmdRCA.Flags().StringVar(&vncPassword, "vnc-password", "abcd1234", "primary password for winvnc")
	cmdRCA.Flags().StringVar(&vncPassword2, "vnc-password-2", "", "secondary password for winvnc")
	cmdRCA.Flags().BoolVar(&vncQueryAccept, "vnc-query-accept", true, "automatically accept connection after timeout")
	cmdRCA.Flags().BoolVar(&vncQueryReject, "vnc-query-reject", false, "automatically decline connection after timeout")
	cmdRCA.Flags().StringVar(&vncQueryTimeout, "vnc-query-timeout", "10", "timeout seconds")
	cmdRCA.Flags().BoolVar(&vncQueryIfNoLogon, "vnc-query-if-no-logon", true, "pop up query if no user is logged in")
	cmdRCA.Flags().StringVar(&sshTrustKey, "ssh-trust-key", "", "SSH server authorized key file")

	cmdRCA.Flags().StringVarP(&rcaUsername, "username", "u", "", "username for authentication")
	cmdRCA.Flags().StringVarP(&rcaPassword, "password", "p", "", "password for authentication")
	cmdRCA.Flags().StringVar(&rcaAuthURL, "auth-url", "", "authentication url")
	cmdRCA.Flags().StringVar(&rcaDisURL, "dis-url", "", "disconnect url")
	cmdRCA.Flags().StringVar(&rcaServerAddr, "server-addr", "127.0.0.1", "rsa server address")
	cmdRCA.Flags().StringVar(&rcaServerPort, "server-port", "7000", "rsa server port")
	cmdRCA.Flags().BoolVarP(&rcaTLS, "tls", "l", false, "enable tls")

	cmdRoot.PersistentFlags().StringVarP(&token, "token", "t", "", "token for rsa and rca(should be same)")

	cmdRSA.Flags().StringVar(&rsaBindAddr, "bind-addr", "127.0.0.1", "rsa bind address")
	cmdRSA.Flags().StringVar(&rsaBindPort, "bind-port", "7000", "rsa bind port")

	home := os.Getenv("HOME")
	if home == "" {
		log.Println("[ERROR]: $HOME env is not set, please set it")
	}

	pathToServiceTreeLinux = home + "/ServiceTree"
}

var cmdRoot = &cobra.Command{
	Use:   "installer",
	Short: "default installer for rca or rsa",
	RunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
}

var cmdRCA = &cobra.Command{
	Use:   "rca",
	Short: "install rca client (only Windows)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if strings.Contains(runtime.GOOS, "linux") {
			return errors.New("[ERROR]: rca can't be built on Linux")
		}
		var err error

		//setting working directory
		err = os.Chdir("..\\")
		if err != nil {
			log.Fatal("[ERROR]: changing directory: " + err.Error())
		}

		workingDir, err = os.Getwd()
		if err != nil {
			log.Fatal("[ERROR]: getting working dir: " + err.Error())
		}

		err = buildRCA()
		if err != nil {
			return err
		}

		err = modifyINIVNC()
		if err != nil {
			return err
		}

		err = callSetPaswd()
		if err != nil {
			return err
		}

		err = modifyINIRCA()
		if err != nil {
			return err
		}

		err = createServiceVNC()
		if err != nil {
			return err
		}

		err = createServiceSSH()
		if err != nil {
			return err
		}

		err = createNSSMRCA()
		if err != nil {
			return err
		}

		return nil
	},
}

var cmdRSA = &cobra.Command{
	Use:   "rsa",
	Short: "install rsa server (only Linux)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if strings.Contains(runtime.GOOS, "windows") {
			return errors.New("[ERROR]: rsa can't be built on Windows")
		}

		var err error

		//setting working directory
		err = os.Chdir("../")
		if err != nil {
			log.Fatal("[ERROR]: changing directory: " + err.Error())
		}

		workingDir, err = os.Getwd()
		if err != nil {
			log.Fatal("[ERROR]: getting working dir: " + err.Error())
		}

		err = buildRSA()
		if err != nil {
			return err
		}

		err = modifyINIRSA()
		if err != nil {
			return err
		}

		//won't work
		// err = createServiceRSA()
		// if err != nil {
		// 	return err
		// }

		return nil
	},
}

func Execute() {
	if err := cmdRoot.Execute(); err != nil {
		os.Exit(1)
	}
}

func buildRCA() error {
	log.Println("[INFO]: building rca.exe")

	wd, err := os.Getwd()
	if err != nil {
		return errors.New("[ERROR]: getting working dir: " + err.Error())
	}

	err = os.Chdir(workingDir + "\\frp")
	if err != nil {
		return errors.New("[ERROR]: changing working dir to \\frp: " + err.Error())
	}

	cmd := exec.Command("go", "build", "-o", pathToServiceTreeWindows+"\\rca\\rca.exe", ".\\cmd\\frpc\\")
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout

	if err := cmd.Run(); err != nil {
		return errors.New("[ERROR]: running go build command")
	}

	err = os.Chdir(wd)
	if err != nil {
		return fmt.Errorf("Changing working dir to %s: %s", wd, err.Error())
	}

	return nil
}

func buildRSA() error {
	log.Println("[INFO]: building rsa")

	wd, err := os.Getwd()
	if err != nil {
		return errors.New("[ERROR]: getting working dir: " + err.Error())
	}

	err = os.Chdir(workingDir + "/frp")
	if err != nil {
		return errors.New("[ERROR]: changing working dir to /frp: " + err.Error())
	}

	cmd := exec.Command("go", "build", "-o", pathToServiceTreeLinux+"/rsa/rsa", "./cmd/frps")
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout

	if err := cmd.Run(); err != nil {
		return errors.New("[ERROR]: running go build command")
	}

	err = os.Chdir(wd)
	if err != nil {
		return fmt.Errorf("Changing working dir to %s: %s", wd, err.Error())
	}

	log.Println("[INFO]: building rsa done")

	return nil
}

// modifyINIVNC creates an .ini file for WinVNC and adds configuration to it
func modifyINIVNC() error {
	log.Println("[INFO]: modifying winvnc.ini file")

	wd, err := os.Getwd()
	if err != nil {
		return errors.New("[ERROR]: getting working dir: " + err.Error())
	}

	err = os.Chdir(pathToServiceTreeWindows)
	if err != nil {
		return fmt.Errorf("[ERROR]: changing working dir to %s: %s", pathToServiceTreeWindows, err.Error())
	}

	_, err = os.Open("winvnc.ini")
	if err != nil {
		if os.IsNotExist(err) {
			_, err = os.Create("winvnc.ini")
			if err != nil {
				return errors.New("[ERROR]: creating wivnc.ini file: " + err.Error())
			}
		} else {
			return errors.New("[ERROR]: opening winvnc.ini file: " + err.Error())
		}
	}

	f, err := ini.Load("winvnc.ini")
	if err != nil {
		return errors.New("[ERROR]: loading wivnc.ini file: " + err.Error())
	}

	//setting values in .ini file
	if vncQueryAccept || vncQueryReject {
		f.Section("admin").Key("QuerySetting").SetValue("4")
	}
	if vncQueryAccept && !vncQueryReject {
		f.Section("admin").Key("QueryAccept").SetValue("1")
	}
	if vncQueryIfNoLogon {
		f.Section("admin").Key("QueryIfNoLogon").SetValue("1")
	}
	if vncQueryAccept || vncQueryReject {
		f.Section("admin").Key("QueryTimeout").SetValue(vncQueryTimeout)
	}

	f.Section("PASSWORD").Key("passwd").SetValue(vncPassword)
	if vncPassword2 != "" {
		f.Section("PASSWORD").Key("passwd2").SetValue(vncPassword2)
	}

	if err := f.SaveTo("winvnc.ini"); err != nil {
		return errors.New("[ERROR]: saving wivnc.ini file: " + err.Error())
	}

	err = os.Chdir(wd)
	if err != nil {
		return fmt.Errorf("[ERROR]: changing working dir to %s: %s", wd, err.Error())
	}

	log.Println("[INFO]: modifying winvnc.ini file done")

	return nil
}

func modifyINIRCA() error {
	log.Printf("[INFO]: Modifying rca.ini file.\n")

	if rcaUsername == "" || rcaPassword == "" || rcaAuthURL == "" || rcaDisURL == "" {
		return errors.New("[ERROR]: username | password | auth-url | dis-url can't be empty")
	}

	wd, err := os.Getwd()
	if err != nil {
		return errors.New("[ERROR]: getting working dir: " + err.Error())
	}

	err = os.Chdir(pathToServiceTreeWindows + "\\rca")
	if err != nil {
		return fmt.Errorf("[ERROR]: changing working dir to %s: %s", pathToServiceTreeWindows+"\\rca", err.Error())
	}

	_, err = os.Open("rca.ini")
	if err != nil {
		if os.IsNotExist(err) {
			_, err = os.Create("rca.ini")
			if err != nil {
				return errors.New("[ERROR]: creating rca.ini file: " + err.Error())
			}
		} else {
			return errors.New("[ERROR]: opening rca.ini file: " + err.Error())
		}
	}

	f, err := ini.Load("rca.ini")
	if err != nil {
		return errors.New("[ERROR]: loading rca.ini file: " + err.Error())
	}

	f.Section("common").Key("username").SetValue(rcaUsername)
	f.Section("common").Key("password").SetValue(rcaPassword)
	f.Section("common").Key("auth_url").SetValue(rcaAuthURL)
	f.Section("common").Key("disconnect_url").SetValue(rcaDisURL)
	f.Section("common").Key("server_addr").SetValue(rcaServerAddr)
	f.Section("common").Key("server_port").SetValue(rcaServerPort)
	if token != "" {
		f.Section("common").Key("token").SetValue(token)
	}
	if rcaTLS {
		f.Section("common").Key("tls_enable").SetValue("true")
	} else {
		f.Section("common").Key("tls_enable").SetValue("false")
	}

	err = f.SaveTo("rca.ini")
	if err != nil {
		return errors.New("[ERROR]: saving rca.ini file: " + err.Error())
	}

	err = os.Chdir(wd)
	if err != nil {
		return fmt.Errorf("[ERROR]: changing working dir to %s: %s", wd, err.Error())
	}

	log.Printf("[INFO]: Modifying rca.ini file DONE !\n")

	return nil
}

func modifyINIRSA() error {
	log.Println("[INFO]: modifying rsa.ini file")

	wd, err := os.Getwd()
	if err != nil {
		return errors.New("[ERROR]: getting working dir: " + err.Error())
	}

	err = os.Chdir(pathToServiceTreeLinux + "/rsa")
	if err != nil {
		return fmt.Errorf("[ERROR]: changing working dir to %s: %s", pathToServiceTreeLinux, err.Error())
	}

	_, err = os.Open("rsa.ini")
	if err != nil {
		if os.IsNotExist(err) {
			_, err = os.Create("rsa.ini")
			if err != nil {
				return errors.New("[ERROR]: creating rsa.ini file: " + err.Error())
			}
		} else {
			return errors.New("[ERROR]: opening rsa.ini file: " + err.Error())
		}
	}

	f, err := ini.Load("rsa.ini")
	if err != nil {
		return errors.New("[ERROR]: loading rsa.ini file: " + err.Error())
	}

	f.Section("common").Key("bind_addr").SetValue(rsaBindAddr)
	f.Section("common").Key("bind_port").SetValue(rsaBindPort)
	if token != "" {
		f.Section("common").Key("token").SetValue(token)
	}

	err = f.SaveTo("rsa.ini")
	if err != nil {
		return errors.New("[ERROR]: saving rsa.ini file: " + err.Error())
	}

	err = os.Chdir(wd)
	if err != nil {
		return fmt.Errorf("[ERROR]: changing working dir to %s: %s", wd, err.Error())
	}

	log.Printf("[INFO]: modifying rsa.ini file DONE !\n")

	return nil
}

func callSetPaswd() error {
	log.Printf("[INFO]: Running setpasswd.exe with password %s\n", vncPassword)

	if vncPassword2 != "" {
		cmd := exec.Command(pathToServiceTreeWindows+"\\"+"setpasswd.exe", vncPassword, vncPassword2)
		err := cmd.Run()
		if err != nil {
			return errors.New("[ERROR]: running setpasswd.exe: " + err.Error())
		}
	} else {
		cmd := exec.Command(pathToServiceTreeWindows+"\\"+"setpasswd.exe", vncPassword)
		err := cmd.Run()
		if err != nil {
			return errors.New("[ERROR]: running setpasswd.exe: " + err.Error())
		}
	}

	return nil
}

func downloadSSHTrustKey(url string) error {
	var err error

	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("[ERROR]: can't download file from %s: %s", url, err.Error())
	}
	defer resp.Body.Close()

	f := new(os.File)
	defer f.Close()

	if _, err := os.Stat("C:\\ProgramData\\.ServiceTree\\authorized_keys"); os.IsNotExist(err) {
		f, err = os.Create("C:\\ProgramData\\.ServiceTree\\authorized_keys")
	} else {
		f, err = os.OpenFile("C:\\ProgramData\\.ServiceTree\\authorized_keys", os.O_WRONLY, os.ModeAppend)
	}

	b, err := io.Copy(f, resp.Body)
	if b == 0 {
		return errors.New("[ERROR]: couldn't copy authorized_keys")
	} else if err != nil {
		return errors.New("[ERROR]: copy authorized_keys: " + err.Error())
	}

	return nil
}

func copySSHTrustKey(path string) error {
	var err error

	f := new(os.File)
	defer f.Close()

	if _, err := os.Stat("C:\\ProgramData\\.ServiceTree\\authorized_keys"); os.IsNotExist(err) {
		f, err = os.Create("C:\\ProgramData\\.ServiceTree\\authorized_keys")
	} else {
		f, err = os.OpenFile("C:\\ProgramData\\.ServiceTree\\authorized_keys", os.O_WRONLY, os.ModeAppend)
	}

	f2, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("[ERROR]: couldn't open file %s: %s", path, err.Error())
	}

	b, err := io.Copy(f, f2)
	if b == 0 {
		return errors.New("[ERROR]: couldn't copy authorized_keys")
	} else if err != nil {
		return errors.New("[ERROR]: copy authorized_keys: " + err.Error())
	}

	return nil
}

func createServiceSSH() error {
	log.Println("[INFO]: creating ServiceTree-ssh service")

	cmd := new(exec.Cmd)

	cmd = exec.Command("dism", "/online", "/Add-Capability", "/CapabilityName:OpenSSH.Server~~~~0.0.1.0")
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		return errors.New("[ERROR]: running powershell command fail: " + err.Error())
	}

	/* this part is done in script
	if _, err := os.Stat("C:\\ProgramData\\ssh"); os.IsNotExist(err) {
		err = os.MkdirAll("C:\\ProgramData\\ssh", 0755)
		if err != nil {
			return errors.New("[ERROR]: creating C:\\ProgramData\\ssh directory failed: " + err.Error())
		}
	}

	cmd = exec.Command("ssh-keygen", "-A")
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		return errors.New("[ERROR]: running ssh-keygen command fail: " + err.Error())
	}
	*/

	//check if user provided url or path to file
	if sshTrustKey != "" {
		_, err := url.ParseRequestURI(sshTrustKey)
		if err == nil {
			err := copySSHTrustKey(sshTrustKey)
			if err != nil {
				return err
			}
		} else {
			err := downloadSSHTrustKey(sshTrustKey)
			if err != nil {
				return err
			}
		}
	}

	cmd = exec.Command("sc", "create", "ServiceTree-ssh", "binPath="+pathToSSH+" -f "+workingDir+"\\config\\sshd_config", "start=auto")
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		return errors.New("[ERROR]: running sc create ServiceTree-ssh fail: " + err.Error())
	}

	cmd = exec.Command("sc", "start", "ServiceTree-ssh")
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		return errors.New("[ERROR]: running sc start ServiceTree-ssh fail: " + err.Error())
	}

	log.Println("[INFO]: creating ServiceTree-ssh done")

	return nil
}

func createServiceVNC() error {
	log.Println("[INFO]: creating ServiceTree-winvnc service")

	wd, err := os.Getwd()
	if err != nil {
		return errors.New("[ERROR]: getting working dir: " + err.Error())
	}

	err = os.Chdir(pathToServiceTreeWindows)
	if err != nil {
		return fmt.Errorf("[ERROR]: changing working dir to %s: %s", pathToServiceTreeWindows, err.Error())
	}

	cmd := new(exec.Cmd)

	cmd = exec.Command("sc", "create", "ServiceTree-winvnc", "binPath="+pathToServiceTreeWindows+"\\winvnc.exe -service", "start=auto")
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		return errors.New("[ERROR]: running sc create ServiceTree-winvnc fail: " + err.Error())
	}

	cmd = exec.Command("sc", "start", "ServiceTree-winvnc")
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		return errors.New("[ERROR]: running sc start ServiceTree-winvnc fail: " + err.Error())
	}

	err = os.Chdir(wd)
	if err != nil {
		return fmt.Errorf("[ERROR]: changing working dir to %s: %s", wd, err.Error())
	}

	log.Println("[INFO]: creating ServiceTree-winvnc service done")

	return nil
}

func createServiceRSA() error {
	var err error
	cmd := new(exec.Cmd)

	cmd = exec.Command("cp", workingDir+"/rsa.service", "/lib/systemd/system")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err = cmd.Run(); err != nil {
		return errors.New("[ERROR]: running cp command")
	}

	cmd = exec.Command("systemctl", "daemon-reload")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err = cmd.Run(); err != nil {
		return errors.New("[ERROR]: running systemctl daemon-reload command")
	}

	cmd = exec.Command("systemctl", "enable", "rsa.service")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err = cmd.Run(); err != nil {
		return errors.New("[ERROR]: running systemctl enable command")
	}

	return nil
}

func createNSSMRCA() error {
	log.Printf("[INFO]: creating RCA NSSM service\n")

	wd, err := os.Getwd()
	if err != nil {
		return errors.New("[ERROR]: getting working dir: " + err.Error())
	}

	if runtime.GOARCH == "386" {
		err = os.Chdir(workingDir + "\\NSSM\\i386")
		if err != nil {
			return fmt.Errorf("[ERROR]: changing dir to %s: %s", "..\\NSSM\\i386", err.Error())
		}
	} else {
		err = os.Chdir(workingDir + "\\NSSM\\amd64")
		if err != nil {
			return fmt.Errorf("[ERROR]: changing dir to %s: %s", "..\\NSSM\\i386", err.Error())
		}
	}

	cmd := new(exec.Cmd)

	cmd = exec.Command("nssm.exe", "install", "ServiceTree-rca", pathToServiceTreeWindows+"\\rca\\rca.exe")
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		return errors.New("[ERROR]: running nssm.exe install ServiceTree-rca")
	}

	cmd = exec.Command("nssm.exe", "set", "ServiceTree-rca", "AppStdout", pathToServiceTreeWindows+"\\rca\\rca_stdout.log")
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		return errors.New("[ERROR]: running nssm.exe set ServiceTree-rca AppStdout")
	}

	cmd = exec.Command("nssm.exe", "set", "ServiceTree-rca", "AppStderr", pathToServiceTreeWindows+"\\rca\\rca_stderr.log")
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		return errors.New("[ERROR]: running nssm.exe set ServiceTree-rca AppStderr")
	}

	cmd = exec.Command("nssm.exe", "start", "ServiceTree-rca")
	if err := cmd.Run(); err != nil {
		//intentionally no error checking
	}

	err = os.Chdir(wd)
	if err != nil {
		return fmt.Errorf("[ERROR]: changing dir to %s: %s", wd, err.Error())
	}

	log.Printf("[INFO]: creating RCA NSSM service done\n")

	return nil
}
