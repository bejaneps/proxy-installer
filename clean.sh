#!/bin/bash

GOPATH="" 
GO111MODULE=""

# removing root directory of ServiceTree
rm -rf $HOME/ServiceTree
rm /lib/systemd/system/rsa.service
rm -rf pkg