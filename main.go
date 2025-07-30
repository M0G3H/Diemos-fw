package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func main() {
	db, err := openRuleDB("/lib/Diemos-fw.db")
	if db != nil {
		defer db.Close()
	}
	if err != nil {
		fmt.Println("can not open db")
		os.Exit(1)
	}

	args := os.Args[1:]
	if len(args) == 1 && args[0] == "restore" {

		defaultPolicy, err := getDefaultPolicyFromDB(db)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		if defaultPolicy == "" {
			defaultPolicy = "allow"
			err = setDefaultPolicyInDB(db, defaultPolicy)
			if err != nil {
				fmt.Println(err)
			}
		}

		action := defaultPolicy
		if action != "allow" && action != "deny" {
			fmt.Println("Only allow or deny actions supported with --all")
			os.Exit(1)
		}
		policy := "ACCEPT"
		if action == "deny" {
			policy = "DROP"
		}

		tools := []string{"iptables", "ip6tables"}
		chains := []string{"INPUT", "OUTPUT"}

		for _, tool := range tools {
			for _, chain := range chains {
				cmd := fmt.Sprintf("%s -P %s %s", tool, chain, policy)
				runCommandSilently(cmd)
			}
		}

		rules, err := getAllRules(db)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		for _, r := range rules {
			commitRules(r.Host, r.Proto, r.Port, r.Action, false)
		}

		return
	} else if len(args) == 1 && (args[0] == "show") {

		rules, err := getAllRules(db)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		defaultPolicy, err := getDefaultPolicyFromDB(db)
		if err != nil {
			defaultPolicy = "error"
		}

		fmt.Printf("{\"all\": \"%s\", \"rules\": [", defaultPolicy)
		for ridx, r := range rules {
			fmt.Printf("{\"action\": \"%s\", \"host\": \"%s\", \"proto\": \"%s\", \"port\": \"%s\"}", r.Action, r.Host, r.Proto, r.Port)
			if ridx != len(rules)-1 {
				fmt.Printf(", ")
			}
		}

		fmt.Printf("]}\n")
		return

	} else if len(args) >= 2 && (args[1] == "--all") {
		action := args[0]
		if action != "allow" && action != "deny" {
			fmt.Println("Only allow or deny actions supported with --all")
			os.Exit(1)
		}
		policy := "ACCEPT"
		if action == "deny" {
			policy = "DROP"
		}

		tools := []string{"iptables", "ip6tables"}
		chains := []string{"INPUT", "OUTPUT"}

		for _, tool := range tools {
			for _, chain := range chains {
				cmd := fmt.Sprintf("%s -P %s %s", tool, chain, policy)
				runCommandSilently(cmd)
			}
		}
		err := setDefaultPolicyInDB(db, action)
		if err != nil {
			fmt.Println("[ERROR] Failed to store default policy in DB:", err)
		}
		return

	} else if len(args) < 7 {
		fmt.Println("Usage: Diemos-fw allow|deny [--all] --host <ip|any> --proto <tcp|udp|icmp|any> --port <port|any> [--delete]")
		os.Exit(1)
	}

	action := args[0]
	delete := false
	if args[len(args)-1] == "--delete" {
		delete = true
		args = args[:len(args)-1]
	}

	host := getArgValue(args, "--host")
	proto := getArgValue(args, "--proto")
	port := getArgValue(args, "--port")

	err = commitRules(host, proto, port, action, delete)
	if err == nil {
		if delete {
			err = delRuleFromDB(db, Rule{Host: host, Proto: proto, Port: port, Action: action})
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		} else {
			err = addRuleToDB(db, Rule{Host: host, Proto: proto, Port: port, Action: action})
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		}
	} else {
		fmt.Println(err)
		os.Exit(1)
	}
}

func commitRules(host, proto, port, action string, delete bool) error {
	if err := validatePort(port); err != nil {
		fmt.Println("Invalid port:", err)
		return err
	}

	hostType := detectHostType(host)
	if hostType == "invalid" {
		return fmt.Errorf("invalid host")
	}

	var commands []string
	if hostType == "ipv4" || hostType == "any" {
		cmds := buildCommands("iptables", action, host, proto, port, delete)
		commands = append(commands, cmds...)
	}
	if hostType == "ipv6" || hostType == "any" {
		cmds := buildCommands("ip6tables", action, host, proto, port, delete)
		commands = append(commands, cmds...)
	}

	for _, cmd := range commands {
		err := runCommandSilently(cmd)
		if err != nil {
			return err
		}
	}

	return nil
}

func getArgValue(args []string, key string) string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == key {
			return args[i+1]
		}
	}
	return ""
}

func validatePort(port string) error {
	if port == "any" {
		return nil
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("port must be between 1-65535 or 'any'")
	}
	return nil
}

func detectHostType(host string) string {
	if host == "any" {
		return "any"
	}
	if strings.Contains(host, "/") {
		ip, _, err := net.ParseCIDR(host)
		if err != nil {
			return "invalid"
		}
		if ip.To4() != nil {
			return "ipv4"
		}
		return "ipv6"
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "invalid"
	}
	if ip.To4() != nil {
		return "ipv4"
	}
	return "ipv6"
}

func buildCommands(tool, action, host, proto, port string, delete bool) []string {
	var commands []string
	chains := []string{"INPUT", "OUTPUT"}
	mangleChains := []string{"PREROUTING", "POSTROUTING"}

	for _, chain := range append(chains, mangleChains...) {
		cmd := []string{}
		if chain == "PREROUTING" || chain == "POSTROUTING" {
			cmd = append(cmd, "-t", "mangle")
		}
		if delete {
			cmd = append(cmd, "-D", chain)
		} else {
			cmd = append(cmd, "-I", chain)
		}

		if host != "any" {
			if chain == "INPUT" || chain == "PREROUTING" {
				cmd = append(cmd, "-s", host)
			} else {
				cmd = append(cmd, "-d", host)
			}
		}
		if proto != "any" {
			cmd = append(cmd, "-p", proto)
		}
		if port != "any" && proto != "icmp" && proto != "any" {
			if chain == "INPUT" || chain == "PREROUTING" {
				cmd = append(cmd, "--dport", port)
			} else {
				cmd = append(cmd, "--sport", port)
			}
		}

		if action == "allow" {
			cmd = append(cmd, "-j", "ACCEPT")
		} else {
			cmd = append(cmd, "-j", "DROP")
		}

		commands = append(commands, tool+" "+strings.Join(cmd, " "))
	}

	return commands
}

func runCommandSilently(cmdStr string) error {
	// fmt.Println("[DEBUG] Executing:", cmdStr) // ← Debug output
	parts := strings.Fields(cmdStr)
	cmd := exec.Command(parts[0], parts[1:]...)
	err := cmd.Run()
	if err != nil {
		return err
	}

	return nil
}
