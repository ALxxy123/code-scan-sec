#!/usr/bin/env bash

log() {
  LEVEL=$1
  shift
  echo "[$LEVEL] $*" >&2
}

RULES=(
  "API_KEY"
  "api_key"
  "apikey"
  "secret"
  "password"
  "token"
  "Authorization"
  "/admin"
  "/debug"
  ".env"
  "config.php"
  "credentials.json"
)

load_config() {
  return 0
}
