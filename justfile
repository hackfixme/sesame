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


[positional-arguments]
lint *args:
  #!/usr/bin/env bash
  set -eEuo pipefail

  # If >0, output statistics only, and write a report file with all issues.
  # Always exits with code 0.
  report=0
  # If >0, limit the number of shown issues.
  limit=0
  # If >0, outputs statistics when report=0.
  stats=1
  # If >0, listen to changes in Go files, and trigger `just lint` again.
  # Requires https://github.com/watchexec/watchexec
  watch=0

  args=(--timeout=5m --output.tab.path=stdout --allow-parallel-runners)

  # It would be nice if Just supported recipe flags, so we could avoid manually
  # parsing arguments. See https://github.com/casey/just/issues/476
  while [ "$#" -gt 0 ]; do
    case $1 in
      -r|--report)      report=1 ;;
      -l=*|--limit=*)   limit="${1##*=}" ;;
      -s=*|--stats=*)   stats="${1##*=}" ;;
      -w|--watch)       watch=1 ;;
      # Other options are passed through to golangci-lint
      *)                args+=("$1") ;;
    esac
    shift
  done

  if [ "$watch" -gt 0 ]; then
    watchargs=(--quiet --shell=none --clear=reset --filter '*.go' --restart
               --debounce 500ms --stop-timeout 1s)
    watchexec "${watchargs[@]}" -- sh -c "just lint --limit=${limit} --stats=${stats}"
    exit $?
  fi

  if [ "$report" -gt 0 ]; then
    args+=(--issues-exit-code=0)
  fi

  # Temporarily disable exit on error so that we process the output
  # ourselves, regardless of the exit code of golangci-lint.
  set +e
  output_gci="$(golangci-lint run "${args[@]}" ./...)"
  gci_exit_code=$?
  set -e

  issues="$(echo -n "$output_gci" | sed '/^[0-9]* issues:$/q' | head -n -1)"
  issues_sorted="$(echo -n "$issues" | sort -t: -k1,1 -k2,2n -k3,3n)"
  issues_count="$(echo "$output_gci" | grep -o '^[0-9]* issues')"
  issues_stats="$(echo -n "$output_gci" | sed -n '/^[0-9]* issues:$/,$p' | tail -n +2)"
  issues_stats_sorted="$(echo -n "$issues_stats" | sort -t':' -k2 -nr)"
  issues_stats_columns="$(echo -n "$issues_stats_sorted" | sed 's/^* //' | column -t -s':')"

  if [ "$report" -gt 0 ]; then
    _report_id="$(date '+%Y%m%d')-$(git describe --tags --abbrev=10 --always)"
    echo -n "$issues_sorted" > "golangci-lint-${_report_id}.txt"
    if [ -n "$issues" ]; then
      issues_stats_columns="${issues_stats_columns}\n"
    fi
    echo -e -n "$issues_stats_columns" > "golangci-lint-stats-${_report_id}.txt"
    echo "$issues_count" >> "golangci-lint-stats-${_report_id}.txt"
    cat "golangci-lint-stats-${_report_id}.txt"
  else
    if [ "$limit" -gt 0 ]; then
      issues_sorted="$(echo "$issues_sorted" | head "-${limit}")"
    fi
    if [ -n "$issues" ]; then
      output="${issues_sorted}\n\n"
      if [ "$stats" -gt 0 ]; then
        output="${output}${issues_stats_columns}\n"
      fi
    fi
    echo -n -e "${output:-}"
    echo "$issues_count"
  fi

  exit "$gci_exit_code"


[positional-arguments]
test *args:
  #!/usr/bin/env bash
  set -eEuo pipefail

  cov=0
  unit=0
  integ=0
  pkgs=()
  argsa=(-v -race -count=1 -failfast)
  argsb=()

  # It would be nice if Just supported recipe flags, so we could avoid manually
  # parsing arguments. See https://github.com/casey/just/issues/476
  while [ "$#" -gt 0 ]; do
    case $1 in
      -c|--coverage)     cov=1 ;;
      -u|--unit)         unit=1 ;;
      -i|--integration)  integ=1 ;;
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

  if [ "$unit" -gt 0 ] && [ "$integ" -eq 0 ]; then
    argsa+=(-skip "Integration$")
  fi
  if [ "$integ" -gt 0 ] && [ "$unit" -eq 0 ]; then
    argsa+=(-run "Integration$")
  fi

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
