# Valkyrie-2 REVENGEANCE
Handy all in one tool to scan all private IP address spaces.

Right now I am compiling this program and uploading it as a release binary. Feel free to compile it yourself though.

## Installation

Running from pre-compiled release binary
```
wget https://github.com/Dirkenhymer/Valkyrie-2/releases/download/v0.1.4-beta/valk2
```
Give the binary executable permission and run!
```
chmod +x valk2
./valk2 -h
```

## Development
```
cargo add ping-rs
cargo add pnet
cargo add regex
cargo add dns_lookup
cargo add tokio -F full
```
