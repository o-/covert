# COVERT

A remote shell implementation, transmitting data encoded as artificial network latency.

## Implementation

Data is encoded with pulse position modulation. To transmit a word of n-bytes in p-ppm, the client generates n*8/p pings (+n for parity), each being sent with a certain delay (relative to the timestamp). Each of the 2^p possible timeshifts corresponds to a p-bit string.

The server acks all of the pings, again delaying each of the responses (relative to the time of reception), to encode the next word on its send buffer.

Each word is accepted by the other side with a final ack/nack (delayed/undelayed) packet, if parity matches.

## Limitations

* There is no session handling. The first ip, which sends a ping packet, after the server is started gets the shell.
* Error correction is very basic, there can be transmission errors.
* The delay itself is not adaptive, so it might not work over connection with high jitter...

## Usage

```
  # sudo python server.py <bind-to-ip>

  # sudo python client.py <src-ip> <server-ip>
```
