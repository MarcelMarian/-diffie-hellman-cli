#!/usr/bin/expect -f

set ip [lindex $argv 0]
set port [lindex $argv 1]
if {$port eq ""} {set port "22"}

set timeout -1

spawn ssh -p $port root@$ip "mount -o rw,remount /;
  mv /mnt/data/diffie-hellman-service.tar.gz /opt/application-system-containers/diffie-hellman-service.tar.gz;
  docker stack rm diffie-hellman-service;
  set -o allexport
  . /opt/edge-agent/edge-agent-environment
  set +o allexport
  sleep 3
  /opt/edge-agent/app-deploy diffie-hellman-service /opt/application-system-containers/diffie-hellman-service.tar.gz"
expect {
        "fingerprint" {send "yes\r"; exp_continue}
        "password" {send "root\r"; exp_continue}
        eof exit
}
