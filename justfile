set dotenv-load

git_root := `git rev-parse --show-toplevel`
dist := git_root + '/dist'

default:
  @just --list

build:
  @mkdir -p "{{dist}}"
  @go build -o "{{dist}}/sesame" "{{git_root}}/cmd/sesame"

clean:
  @rm -rf "{{dist}}"
