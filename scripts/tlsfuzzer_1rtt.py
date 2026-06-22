# tlsfuzzer_1rtt.py -- minimal tlsfuzzer scenario: drive a 1-RTT
# TLS 1.3 handshake against the server on (host, port) and assert it
# completes. This is a starter scenario; expand the suite as the
# library gains features at J1/J2.
#
# Usage: python3 tlsfuzzer_1rtt.py HOST PORT

import sys
from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import ClientHelloGenerator, \
    ClientKeyExchangeGenerator, ClientFinishedGenerator, \
    ApplicationDataGenerator
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
    ExpectServerFinished, ExpectApplicationData

def main():
    if len(sys.argv) != 3:
        print("usage: tlsfuzzer_1rtt.py HOST PORT", file=sys.stderr)
        sys.exit(2)
    host, port = sys.argv[1], int(sys.argv[2])

    conversation = [
        ClientHelloGenerator({"version": (3, 4)}),
        ExpectServerHello(),
        ExpectCertificate(),
        ExpectServerFinished(),
        ClientKeyExchangeGenerator(),
        ClientFinishedGenerator(),
        ApplicationDataGenerator(b"ping"),
        ExpectApplicationData(),
    ]
    runner = Runner(conversation)
    runner.remote_endpoint = (host, port)
    try:
        runner.run()
    except Exception as e:
        print(f"tlsfuzzer scenario failed: {e}", file=sys.stderr)
        sys.exit(1)
    print("tlsfuzzer_1rtt: ok")

if __name__ == "__main__":
    main()
