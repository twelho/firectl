# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may
# not use this file except in compliance with the License. A copy of the
# License is located at
#
#	http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.
SRCFILES := *.go

all: firectl

firectl: $(SRCFILES)
	go build

build-docker:
	docker run -it --rm -v $(shell pwd):/go/src/github.com/luxas/firectl -w /go/src/github.com/luxas/firectl golang:1.11 make

install:
	cp firectl /usr/local/bin

test:
	go test -v ./...

lint:
	golint $(SRCFILES)

clean:
	go clean

.PHONY: all clean
