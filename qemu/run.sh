#! /bin/bash

BOOTARGS=()

# if [ -z "${STY}" ]; then
#     echo "must be started inside a screen session" >&2
#     exit 1
# fi

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <instance-type> <instance-number>"
    exit 1
fi

INSTANCE_TYPE=$1
INSTANCE_NUMBER=$2

if [[ -z "$INSTANCE_TYPE" || -z "$INSTANCE_NUMBER" ]]; then
    echo "Error: Both arguments are required"
    exit 1
fi

if [[ "$INSTANCE_TYPE" != "witness" && "$INSTANCE_TYPE" != "prover" ]]; then
    echo "Error: First argument must be 'witness' or 'prover'"
    exit 1
fi

if ! [[ "$INSTANCE_NUMBER" =~ ^[1-9][0-9]*$ ]]; then
    echo "Error: Second argument must be a positive integer"
    exit 1
fi

# If the script reaches this point, both arguments are valid
echo "Instance type: $INSTANCE_TYPE"
echo "Instance number: $INSTANCE_NUMBER"

## OpenWrt in QEMU
BASE_IMG=openwrt-22.03.3-x86-64-generic-ext4-combined.img
BOOTARGS+=("-serial" "chardev:charconsole0")

instance_type_id=""
instance_number_id="$(echo "$INSTANCE_NUMBER" | awk '{ printf "%02X",$1 }')"
gdb_port=0

case "$INSTANCE_TYPE" in
    "witness")
        instance_type_id="01"
        gdb_port=$((23000 + $INSTANCE_NUMBER))
        ;;
    "prover")
        instance_type_id="02"
        gdb_port=$((24000 + $INSTANCE_NUMBER))
        ;;
    *)
        echo "Error: INSTANCE_TYPE must be either 'witness' or 'prover'"
        exit 1
        ;;
esac

echo "MAC address: 02:ba:de:af:${instance_type_id}:${instance_number_id}"
echo "GDB port: $gdb_port"

USER="$(whoami)"
BRIDGE=br-qemu

# if bridge doesn't exist, create it
if [ ! -e "/sys/class/net/${BRIDGE}" ]; then
    echo "Creating bridge ${BRIDGE}"
    sudo ip link add "${BRIDGE}" type bridge
    sudo ip link set "${BRIDGE}" up
    sudo ip addr replace 192.168.251.1/24 dev "${BRIDGE}"
fi

# if tap interface doesn't exist, create it
if [ ! -e "/sys/class/net/tap-$INSTANCE_TYPE-$INSTANCE_NUMBER" ]; then
    echo "Creating tap interface tap-$INSTANCE_TYPE-$INSTANCE_NUMBER"
    sudo ip tuntap add dev tap-$INSTANCE_TYPE-$INSTANCE_NUMBER mode tap user "$USER"
    sudo ip link set tap-$INSTANCE_TYPE-$INSTANCE_NUMBER up
    sudo ip link set tap-$INSTANCE_TYPE-$INSTANCE_NUMBER master "${BRIDGE}"
fi

qemu-img create -b "${BASE_IMG}" -f qcow2 $INSTANCE_TYPE-$INSTANCE_NUMBER -F raw
qemu-system-x86_64 -enable-kvm -name "instance-${INSTANCE_TYPE}-${INSTANCE_NUMBER}" \
    -display none -no-user-config -nodefaults \
    -m 1G,maxmem=2G,slots=2 -device virtio-balloon \
    -cpu host -smp 2 -machine q35,accel=kvm,usb=off,dump-guest-core=off \
    -device virtio-scsi-pci \
    -device scsi-hd,drive=drive0 \
    -drive file=$INSTANCE_TYPE-$INSTANCE_NUMBER,if=none,id=drive0,cache=unsafe,discard=unmap \
    -nic tap,ifname=tap-$INSTANCE_TYPE-$INSTANCE_NUMBER,script=no,downscript=no,model=virtio,mac=02:ba:de:af:"${instance_type_id}":"${instance_number_id}" \
    -nic user,model=virtio,mac=06:ba:de:af:"${instance_type_id}":"${instance_number_id}" \
    -gdb tcp:127.0.0.1:$gdb_port \
    -device virtio-rng \
    -device virtio-serial,id=virtio-serial \
    -chardev stdio,id=charconsole0,mux=on,signal=off -mon chardev=charconsole0,mode=readline \
    "${BOOTARGS[@]}"
sleep 1

# -nic vde,sock=num$INSTANCE_NUMBER.ctl,port=1,model=virtio-net-pci,mac=02:ba:de:af:"${instance_type_id}":"${instance_number_id}" \
