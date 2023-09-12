# microps
## Description
An implementation of a small TCP/IP protocol stack for learning.

## Usage
```sh
# Create TAP device.
sudo ip tuntap add mode tap user $USER name tap0
sudo ip addr add 192.0.2.1/24 dev tap0
sudo ip link set tap0 up

# Build.
cd microps
make
```

## Reference
[microps](https://github.com/pandax381/microps)

## License
[MIT](./LICENSE)
