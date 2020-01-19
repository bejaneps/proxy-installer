#!/bin/bash

export GOPATH="$(echo "$PWD")"
export GO111MODULE=on

mkdir build

# building installer
cd frp

# change this path if your go executable is located somewhere else
go build -o ../build/installer ./cmd/installer

cd ..

# creating dirs for ServiceTree
mkdir $HOME/ServiceTree
mkdir $HOME/ServiceTree/rsa
mkdir $HOME/ServiceTree/rca