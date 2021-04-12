/*
Copyright © 2021 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"embed"
	"fmt"
	"github.com/spf13/cobra"
	"io"
	"io/fs"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

var vpnCmd = &cobra.Command{
	Use:   "vpn",
	Short: "Run OpenVPN selectively",
	Long: `Some servers I work on are behind a corporate firewall
so that SSH is only available when connected to the network via a VPN.
This VPN is somehow pretty unstable for me on Linux; I cannot connect to 
a multitude of websites like Stackoverflow or Github, which is pretty annoying 
for any computer engineer as you might imagine. This tool aims to alleviate this. 
It  will configure and start, and stop an openvpn client that only 
tunnels connections to servers that belong to the vpn's domain. By default it also
uses the pass command to gather credentials for the connection. It looks for 
a VPN directory and search any 

Domains are specified at compile time in the domains/ directory as 
a folder which contains the base OpenVPN config (the one you use normally)
and 
`,
	//Run: func(cmd *cobra.Command, args []string) {
	//	fmt.Println("vpn called")
	//},
}

//go:embed domains/*
var domains embed.FS
var validDomains []string

func SetDomainNames() {
	entries, err := domains.ReadDir("domains")
	if err != nil {
		fmt.Print("Malformed domain dir, you will need to recompile: ")
		fmt.Println(err)
		os.Exit(1)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			validDomains = append(validDomains, entry.Name())
		}
	}

}

var additionalHosts []string
var additionalIPs []string
var passwordPath string
var passwordStorePath string


func getServersFromKnownHosts(homedir string, domain string, additionalHosts []string) (map[string]string, error) {
	dat, err := ioutil.ReadFile(homedir + "/.ssh/known_hosts")
	if err != nil {
		return nil, fmt.Errorf("could not read known hosts: %w", err)
	}
	lines := strings.Split(string(dat), "\n")
	serverCandidates := make(map[string]string)
	for _, line := range lines {
		for _, server := range strings.Split(strings.Split(line, " ")[0], ",") {
			if strings.HasSuffix(server, domain) {
				ips, err := net.LookupIP(server)
				if err != nil {
					return nil, fmt.Errorf("could not retrieve ip")
				}
				serverCandidates[server] = ips[0].String()
			}
		}
	}
	for _, host := range additionalHosts {
		ips, err := net.LookupIP(host)
		if err != nil {
			return nil, fmt.Errorf("could not retrieve ip")
		}
		serverCandidates[host] = ips[0].String()
	}

	return serverCandidates, nil
}

var usernameRe = regexp.MustCompile("(?:username|email|user):[ ]*([^\\s]*)")

func getCredentials(passwordPath string) (string, string, error) {
	passCmd := exec.Command("gpg", "-q", "--decrypt", passwordPath)
	stdout, err := passCmd.Output()
	if err != nil {
		// TODO stderr
		return "", "", fmt.Errorf("could not run gpg decrypt: %w", err)
	}
	lines := strings.SplitN(string(stdout), "\n", 2)
	if len(lines) != 2 || len(lines[0]) == 0 {
		return "", "", fmt.Errorf("could not retrieve password from pass command's result")
	}

	matches := usernameRe.FindStringSubmatch(lines[1])
	if len(matches) != 2 {
		return "", "", fmt.Errorf("could not retrieve username from pass command's result")
	}

	return matches[1], lines[0], nil
}

func createVPNFolder(domain string, ips []string) (string, error) {
	confDir := filepath.Join("/tmp/scripts-vpn/", domain)
	if err := os.MkdirAll(confDir, 0700); err != nil {
		return "", fmt.Errorf("could not create temporary config dir for OpenVPN: %w", err)
	}

	//domains.ReadFile(filepath.Join(domain, ""))
	names, err := domains.ReadDir(filepath.Join("domains", domain))
	if err != nil {
		return "", fmt.Errorf("could not list files from domains (recompile needed): %w", err)
	}
	confFilename := ""
	var otherFilenames []string
	for _, entry := range names {
		if filepath.Ext(entry.Name()) == ".ovpn" || filepath.Ext(entry.Name()) == ".conf" {
			confFilename = entry.Name()
		} else if !entry.IsDir() {
			otherFilenames = append(otherFilenames, entry.Name())
		} else {
			return "", fmt.Errorf("domain %s folder should not contain subfolders", domain)
		}
	}

	// openvpn --daemon openvpn-$1 --writepid /var/run/openvpn-client/$1.pid --suppress-timestamps --nobind --cd /etc/openvpn/client/ --config $1.conf --auth-user-pass <(echo -e "$2\n$3")' "bash" "$vpnname" "$username" "$password

	// Adjust config and write to dir
	config, err := domains.ReadFile(filepath.Join("domains", domain, confFilename))
	if err != nil {
		return "", fmt.Errorf("could not read config file from domains (recompile needed): %w", err)
	}



	config = append([]byte(fmt.Sprintf("daemon openvpn-%s\ncd %s\nwritepid lock.pid\nsuppress-timestamps\nnobind\nauth-user-pass creds.txt\n\n", domain, confDir)), config...)

	config = append(config, []byte("\nroute-nopull\n")...)
	for _, ip := range ips {
		config = append(config, []byte(fmt.Sprintf("route %s 255.255.255.255\n", ip))...)
	}
	if err := os.WriteFile(filepath.Join(confDir, "conf.ovpn"), config, 0600); err != nil {
		return "", fmt.Errorf("could not write config file: %w", err)
	}

	// copy everything else into this dir
	for _, fname := range otherFilenames {
		data, err := domains.ReadFile(filepath.Join("domains", domain, fname))
		if err != nil {
			return "", fmt.Errorf("could not read file %s from domains (recompile needed): %w", fname, err)
		}
		if err := os.WriteFile(filepath.Join(confDir, fname), data, 0600); err != nil {
			return "", fmt.Errorf("could not write file %s: t (stderr was %s)%w", fname, err)
		}

	}


	return confDir, nil
}

func exactAndValidArgs(cmd *cobra.Command, args []string) error {
	if exact := cobra.ExactArgs(1)(cmd, args); exact != nil {
		return exact
	}
	if valid := cobra.OnlyValidArgs(cmd, args); valid != nil {
		return valid
	}
	return nil
}

func startVPN(domain string) error {
	fmt.Println("Starting VPN...")
	homedir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("could not got home directory: %w", err)
	}
	servers, err := getServersFromKnownHosts(homedir, domain, additionalHosts)
	if err != nil {
		return fmt.Errorf("could not get hosts: %w", err)
	}
	ips := make([]string, 0, len(servers)  + len(additionalIPs))
	ips = append(ips, additionalIPs...)

	fmt.Println("Using servers:")
	for server, ip := range servers {
		fmt.Printf("%s -> %s\n", server, ip)
		ips = append(ips, ip)
	}
	if len(additionalIPs) > 0 {
		fmt.Println("And additional IPs: ")
	}
	for _, ip := range additionalIPs {
		fmt.Printf("%s\n", ip)
	}

	if passwordStorePath == "" {
		passwordStorePath = filepath.Join(homedir, ".password-store/")
	}

	passwordStorePath, err = filepath.EvalSymlinks(passwordStorePath)
	if err != nil {
		return fmt.Errorf("could not follow symlink of password folder (%s): %w", passwordStorePath, err)
	}

	if passwordPath == "" {
		//files := []string{}
		err := filepath.Walk(passwordStorePath, func(path string, info fs.FileInfo, err error) error {
			if err != nil {
				return err
			}

			fname := info.Name()
			if fname == ".git" {
				return filepath.SkipDir
			}

			if !info.IsDir() && filepath.Ext(fname) == ".gpg" {
				if strings.Contains(path, "vpn") && strings.TrimSuffix(fname, filepath.Ext(fname)) == domain {
					passwordPath = path
					return io.EOF
				}
			}
			return nil
		})
		if err != nil && err != io.EOF || passwordPath == "" {
			return fmt.Errorf("could not find password file in store: %w", err)
		}
	}

	username, password, err := getCredentials(passwordPath)
	if err != nil {
		return fmt.Errorf("could not get credentials: %w", err)
	}
	fmt.Printf("Got credentials from %s\n", passwordPath)


	confPath, err := createVPNFolder(domain, ips)
	if err != nil {
		return fmt.Errorf("could not create config folder: %w", err)
	}
	fmt.Printf("Created temporary config folder %s\n", confPath)

	// write credentials to file
	if err := os.WriteFile(filepath.Join(confPath, "creds.txt"), []byte(fmt.Sprintf("%s\n%s\n", username, password)), 0600); err != nil {
		return fmt.Errorf("could not create creds file: %w", err)
	}
	//
	defer os.Remove(filepath.Join(confPath, "creds.txt"))

	if err = cacheSudo(); err != nil {
		return fmt.Errorf("could not gain super user priviliges: %w", err)
	}

	// openvpn --daemon openvpn-$1 --writepid /var/run/openvpn-client/$1.pid --suppress-timestamps --nobind --cd /etc/openvpn/client/ --config $1.conf --auth-user-pass <(echo -e "$2\n$3")' "bash" "$vpnname" "$username" "$password



	//openvpnCmd := exec.Command("openvpn", "--daemon", fmt.Sprintf("openvpn-%s", domain), "--writepid", filepath.Join(confPath, fmt.Sprintf("%s.pid", domain)), "--suppress-timestamps", "--nobind", "--cd", confPath, "--config", "conf.ovpn")
	openvpnCmd := exec.Command("sudo", "openvpn", "--config", filepath.Join(confPath, "conf.ovpn"), "--auth-user-pass", "creds.txt")
	//openvpnCmd := exec.Command("cat")



	//stdin, err := openvpnCmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("could not create stdin pipe for openvpn process: %w", err)
	}
	//go func() {
	//	// TODO errors
	//	defer stdin.Close()
	//	//time.Sleep(5 * time.Second)
	//	io.WriteString(stdin, fmt.Sprintf("%s\n%s\n", username, password))
	//}()
	//stderr, err := cmd.StderrPipe()
	err = openvpnCmd.Run(); if err != nil {
		return fmt.Errorf("could not start openvpn deamon (system log should contain hints as to why): %w", err)
	}
	//fmt.Printf("%s\n", out)

	fmt.Println("Done! OpenVPN should be up. If not check the system log.")

	return nil
}

var vpnStopCmd = &cobra.Command{
	Use:   "stop <domain>",
	Args:  exactAndValidArgs,
	Short: "Stop OpenVPN",
	Long: `Stop given OpenVPN configuration.
`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Stopping VPN...")
	},
	ValidArgs: validDomains,
}

var vpnPsCmd = &cobra.Command{
	Use:   "ps",
	Short: "List running VPN connections",
	Long: `
`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("ps:")
	},
}

func init() {
	SetDomainNames()

	var vpnStartCmd = &cobra.Command{
		Use:   "start <domain>",
		Args:  exactAndValidArgs,
		Short: "Start OpenVPN",
		Long: `Run OpenVPN instance identified by its root domain with ephemeral configuration.
`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := startVPN(args[0]); err != nil {
				fmt.Print("Could not start VPN: ")
				fmt.Println(err)
			}
		},
		ValidArgs: validDomains,
	}


	rootCmd.AddCommand(vpnCmd)
	vpnCmd.AddCommand(vpnStartCmd)
	vpnCmd.AddCommand(vpnStopCmd)
	vpnCmd.AddCommand(vpnPsCmd)

	vpnStartCmd.Flags().StringSliceVarP(&additionalHosts, "hosts", "s", []string{}, "Additional hosts to include in VPN config.\nShould be the DNS-resolvable hostname.\nCan be specified multiple times or as a comma-separated list.")
	vpnStartCmd.Flags().StringSliceVarP(&additionalIPs, "ips", "i", []string{}, "Additional ips to include in VPN config.\nCan be specified multiple times or as a comma-separated list.")
	vpnStartCmd.Flags().StringVarP(&passwordPath, "password_file", "p", "", "Path to gpg-encrypted password file (unix pass style). Will look in ~/.password-store if not provided")

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// vpnCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// vpnCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
