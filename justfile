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

vm-copy:
  @rsync -avLP --rsync-path="sudo rsync" -e "ssh -F '$SSH_CONFIG'" dist/ sesame-test:/usr/local/bin/

vm-setup:
  #!/usr/bin/env sh
  imgfile="debian-12-genericcloud-amd64-20250428-2096.qcow2"
  absimgfile="{{git_root}}/test/vm/$imgfile"
  test -s "$absimgfile" || \
    wget -c -O "$absimgfile" "https://cloud.debian.org/images/cloud/bookworm/20250428-2096/$imgfile"
  go run "{{git_root}}/test/bin/serve.go" -path "{{git_root}}/test/vm/cloud-init" -address :8100 &
  srvpid=$!
  echo "Booting $imgfile ..."
  qemu.sh -d --backing="$absimgfile" "{{git_root}}/test/vm/debian-12-sesame-test-base.qcow2"
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
