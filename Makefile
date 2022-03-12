#!/usr/bin/make -f

# Copyright (c) 2022  The Go-Enjin Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#: uncomment to echo instead of execute
#CMD=echo

BE_PATH ?= ../../../be
AG_PATH ?= ../../pkg/atlas-gonnect

AG_PACKAGE = github.com/go-enjin/third_party/pkg/atlas-gonnect

ENJENV_BIN ?= $(shell which enjenv)

.PHONY: all help local unlocal tidy build

help:
	@echo "usage: make <help|local|unlocal|tidy>"

build:
	@go build -v -tags atlassian,database

local:
	@if [ -d "${BE_PATH}" ]; then \
		${CMD} ${ENJENV_BIN} go-local ${BE_PATH}; \
	else \
		echo "BE_PATH not set or not a directory: \"${BE_PATH}\""; \
	fi
	@if [ -d "${AG_PATH}" ]; then \
		${CMD} ${ENJENV_BIN} go-local ${AG_PACKAGE} ${AG_PATH}; \
	else \
		echo "AG_PATH not set or not a directory: \"${AG_PATH}\""; \
	fi

unlocal:
	@${CMD} ${ENJENV_BIN} go-unlocal
	@${CMD} ${ENJENV_BIN} go-unlocal ${AG_PACKAGE}

tidy:
	@${CMD} go mod tidy -go=1.16 && go mod tidy -go=1.17

be-update:
	@${CMD} GOPROXY=direct go get -u github.com/go-enjin/be
