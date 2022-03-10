#!/usr/bin/expect -f

set ip [lindex $argv 0]
set filename [lindex $argv 1]
set port [lindex $argv 2]
if {$port eq ""} {set port "22"}

set timeout -1
spawn scp -P $port -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $filename root@$ip:/mnt/data/diffie-hellman-service.tar.gz
expect {
        "fingerprint" {send "yes\r"; exp_continue}
        "password" {send "root\r"; exp_continue}
        eof exit
}
