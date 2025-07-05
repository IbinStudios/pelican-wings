#!/bin/bash
export PATH=/usr/local/go/bin:$PATH
go build -ldflags="-s -w" -o wings-custom