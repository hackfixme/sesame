set dotenv-load

rootdir := `git rev-parse --show-toplevel`
distdir := rootdir + '/dist'
covdir  := rootdir + '/coverage'

default:
  @just --list

build:
  @mkdir -p "{{distdir}}"
  @go build -o "{{distdir}}/sesame" "{{rootdir}}/cmd/sesame"

clean:
  @rm -rf "{{distdir}}" "{{covdir}}" "{{rootdir}}"/golangci-lint*.txt
  @git ls-files --others --exclude-standard | grep '_test\.go' | xargs -r rm

lint report="":
  #!/usr/bin/env sh
  if [ -z '{{report}}' ]; then
    golangci-lint run --timeout=5m --output.tab.path=stdout ./...
    exit $?
  fi

  _report_id="$(date '+%Y%m%d')-$(git describe --tags --abbrev=10 --always)"
  golangci-lint run --timeout 5m --output.tab.path=stdout --issues-exit-code=0 \
      --show-stats=false ./... \
    | tee "golangci-lint-${_report_id}.txt" \
    | awk 'NF {if ($2 == "revive") print $2 ":" $3; else print $2}' \
    | sed 's,:$,,' | sort | uniq -c | sort -nr \
    | tee "golangci-lint-summary-${_report_id}.txt"

[positional-arguments]
test *args:
  #!/usr/bin/env bash
  set -eEuo pipefail

  cov=0
  pkgs=()
  argsa=(-v -race -count=1 -failfast)
  argsb=()

  # It would be nice if Just supported recipe flags, so we could avoid manually
  # parsing arguments. See https://github.com/casey/just/issues/476
  while [ "$#" -gt 0 ]; do
    case $1 in
      -c|--coverage)  cov=1 ;;
      # Other options are passed through to go test
      -*)             argsa+=("$1") ;;
      *)              pkgs+=("$1") ;;
    esac
    shift
  done

  if [ "$cov" -gt 0 ]; then
    mkdir -p "{{covdir}}"
    argsa+=(-coverpkg=./...)
    argsb+=(-args -test.gocoverdir="{{covdir}}")

    echo "Applying Go coverage workaround ..."
    ./bin/fix-missing-go-coverage.sh
  fi

  [ "${#pkgs[@]}" -eq 0 ] && pkgs=(./...)

  go test "${argsa[@]}" "${pkgs[@]}" "${argsb[@]}"

  if [ "$cov" -gt 0 ]; then
    go tool covdata textfmt -i="{{covdir}}" -o "{{covdir}}/coverage.txt"
    fcov report "{{covdir}}/coverage.txt"
  fi

vm-copy:
  @rsync -avLP --rsync-path="sudo rsync" -e "ssh -F '$SSH_CONFIG'" dist/ sesame-test:/usr/local/bin/

vm-setup:
  #!/usr/bin/env sh
  imgfile="debian-12-genericcloud-amd64-20250428-2096.qcow2"
  absimgfile="{{rootdir}}/test/vm/$imgfile"
  test -s "$absimgfile" || \
    wget -c -O "$absimgfile" "https://cloud.debian.org/images/cloud/bookworm/20250428-2096/$imgfile"
  go run "{{rootdir}}/test/bin/serve.go" -path "{{rootdir}}/test/vm/cloud-init" -address :8100 &
  srvpid=$!
  echo "Booting $imgfile ..."
  qemu.sh -d --backing="$absimgfile" "{{rootdir}}/test/vm/debian-12-sesame-test-base.qcow2"
  # Wait for SSH to be reachable. Connections to the QEMU forwarded port are
  # reset while the VM is booting.
  until ssh -F "$SSH_CONFIG" sesame-test 'echo -n' 2> /dev/null; do
    sleep 1
  done
  echo "Waiting for cloud-init to finish"
  ssh -F "$SSH_CONFIG" sesame-test 'cloud-init status --wait'
  echo "Powering off VM ..."
  ssh -F "$SSH_CONFIG" sesame-test 'sudo poweroff'
  pkill -P "$srvpid"

vm-ssh:
  #!/usr/bin/env sh
  until ssh -F "$SSH_CONFIG" sesame-test 'echo -n' 2> /dev/null; do
    sleep 1
  done
  ssh -F "$SSH_CONFIG" sesame-test
