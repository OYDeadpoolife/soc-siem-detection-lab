# auditd rules used by the lab

The auditd detections (DET-06, DET-07) need these rules on the Linux server. **They are a starting point and are NOT TESTED by the author on
a real server.** Audit rules change the behaviour of the monitored machine: apply them only on a lab VM you control.

## Rules (`/etc/audit/rules.d/soc-lab.rules`)

```text
# Reads of the password hash file (key shadow_read). The PAM helper unix_chkpwd also triggers this: exclude it in the query.
-w /etc/shadow -p r -k shadow_read

# Changes to accounts and sudo rules
-w /etc/passwd -p wa -k passwd_changes
-w /etc/group -p wa -k group_changes
-w /etc/sudoers -p wa -k sudoers_changes
-w /etc/sudoers.d/ -p wa -k sudoers_changes

# Account management programs (key user_mgmt)
-w /usr/sbin/useradd -p x -k user_mgmt
-w /usr/sbin/usermod -p x -k user_mgmt
-w /usr/sbin/userdel -p x -k user_mgmt
```

## Load and check them (changes the system: needs administrator rights)

```bash
sudo augenrules --load      # merges /etc/audit/rules.d/*.rules and loads them; prints the loaded rules or an error
sudo auditctl -l            # lists the active rules; you should see the keys above
```

* `-w PATH` watches a file or directory; `-p r|w|x|a` is the access type (read, write, execute, attribute change); `-k KEY` names the rule
  so that a search can find it.
* Check the rules with `sudo ausearch -k shadow_read -i` after running `sudo cat /etc/shadow` yourself; you should see the record.
* Avoid broad rules such as "log every execve" on a production server: they create a very large volume of events.

## Reading a record

```text
type=SYSCALL msg=audit(1773483164.090:408): ... auid=1002 uid=0 ... comm="cat" exe="/usr/bin/cat" key="shadow_read"
```

| Field | Meaning |
|---|---|
| `msg=audit(<epoch>:<serial>)` | Time and the serial number shared by all records of one event |
| `auid` | **Audit login uid**: the user who originally logged in. It does not change with `su` or `sudo` |
| `uid`, `euid` | The user the process runs as |
| `exe`, `comm` | The program and its name |
| `key` | The label from the rule |

The records in `datasets/linux/audit.log` are simplified examples that follow this layout.
