import socket
import threading
import subprocess
import os
import json
import rsa
import pickle
import hashlib
import time
from queue import Queue, Empty

current_processes = {}
subprocesses = {}

def enqueue_output(out, queue):
    for line in iter(out.readline, b''):
        queue.put(line)
    out.close()

def run_application(path):
    pid = threading.get_native_id()
    split_path = os.path.split(path)
    directory = "/".join(split_path[:-1])
    file_name = split_path[-1]
    ret = subprocess.Popen(file_name, cwd=directory, shell=True, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    subprocesses[pid] = ret

def send_confirm_packet(error_code, error_message, client_socket):
    packet = b""
    packet += (0).to_bytes(2, byteorder="big")
    packet += (error_code).to_bytes(2, byteorder="big")
    packet += len(error_message).to_bytes(4, byteorder="big")
    packet += error_message.encode()

    client_socket.send(packet)

def get_cur_json_data():
    with open("./data.json", "r") as f:
        return json.load(f)

if not os.path.exists("./data.json"):
    with open("./data.json", "w") as f:
        f.write('{"apps": {}}')

magic = None
with open("./magic.txt", "rb") as f:
    magic = f.read()

recv_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
recv_socket.bind(("0.0.0.0", 8081))
current_conn = None

while True:
    try:
        recv_socket.listen(1)
        conn, addr = recv_socket.accept()
        current_conn = conn

        recv_type = int.from_bytes(conn.recv(2), byteorder="big")
        if recv_type != 5:
            send_confirm_packet(1, "Invalid packet type", conn)
            conn.close()
            continue
    
        pub_key, priv_key = rsa.newkeys(1024)

        pub_key_bytes = pickle.dumps(pub_key)
        packet = b""
        packet += (2).to_bytes(2, byteorder="big")
        packet += len(pub_key_bytes).to_bytes(4, byteorder="big")
        packet += hashlib.md5(pub_key_bytes).digest()
        packet += pub_key_bytes

        conn.sendall(packet)

        recv_magic = rsa.decrypt(conn.recv(128), priv_key)
        if recv_magic != magic:
            send_confirm_packet(1, "Invalid magic number", conn)
            conn.close()
            continue

        recv_type = int.from_bytes(conn.recv(2), byteorder="big")

        if recv_type == 0:
            send_packet = b""
            send_packet += (3).to_bytes(2, byteorder="big")

            cur_json_data = get_cur_json_data()
            send_packet += len(cur_json_data["apps"]).to_bytes(2, byteorder="big")
            for app in cur_json_data["apps"]:
                send_packet += len(cur_json_data["apps"][app]["name"]).to_bytes(2, byteorder="big")
                send_packet += int(app).to_bytes(2, byteorder="big")
                send_packet += cur_json_data["apps"][app]["name"].encode()
            
            conn.sendall(send_packet)

        elif recv_type == 1:
            send_packet = b""
            send_packet += (4).to_bytes(2, byteorder="big")
            send_packet += len(current_processes).to_bytes(2, byteorder="big")

            for process in current_processes:
                subproc_pid = subprocesses[process].pid 
                is_alive_output = subprocess.check_output(['tasklist', '/fi', f'pid eq {subproc_pid}']).decode()
                is_alive = "No tasks" not in is_alive_output

                send_packet += len(current_processes[process]["name"]).to_bytes(2, byteorder="big")
                send_packet += (0 if is_alive else 1).to_bytes(2, byteorder="big")
                send_packet += process.to_bytes(4, byteorder="big")
                send_packet += current_processes[process]["name"].encode()
            
            conn.send(send_packet)
            

        elif recv_type == 2:
            recv_app_id = int.from_bytes(conn.recv(2), byteorder="big")
            cur_json_data = get_cur_json_data()
            print("!!!")
            if not os.path.exists(cur_json_data["apps"][str(recv_app_id)]["path"]):
                print("???")
                send_confirm_packet(1, "Path not present on computer", conn)
                continue

            new_thread = threading.Thread(target=run_application, args=(cur_json_data["apps"][str(recv_app_id)]["path"],))
            new_thread.start()
            current_processes[new_thread.native_id] = {"name": cur_json_data["apps"][str(recv_app_id)]["name"], "thread": new_thread}
            send_confirm_packet(0, "", conn)

        elif recv_type == 3:
            recv_proc_pid = int.from_bytes(conn.recv(4), byteorder="big")
            is_alive_output = subprocess.check_output(['tasklist', '/fi', f'pid eq {recv_proc_pid}']).decode()
            if "No tasks" not in is_alive_output:
                subprocess.check_output("Taskkill /PID %d /F" % subprocesses[recv_proc_pid].pid)
            current_processes[recv_proc_pid]["thread"].join()
            del current_processes[recv_proc_pid]
            send_confirm_packet(0, "", conn)
        elif recv_type == 4:
            recv_proc_pid = int.from_bytes(conn.recv(4), byteorder="big")
            stdout = ""
            stderr = ""

            q = Queue()
            t = threading.Thread(target=enqueue_output, args=(subprocesses[recv_proc_pid].stdout, q))
            t.start()

            try:
                while True:
                    stdout += q.get_nowait().decode()
            except Empty:
                pass

            q = Queue()
            t = threading.Thread(target=enqueue_output, args=(subprocesses[recv_proc_pid].stderr, q))
            t.start()

            try:
                while True:
                    stderr += q.get_nowait().decode()
            except Empty:
                pass

            log = f"stdout:\n{stdout}\nstderr:\n{stderr}"
            send_packet = b""
            send_packet += (1).to_bytes(2, byteorder="big")
            send_packet += len(log).to_bytes(4, byteorder="big")
            send_packet += log.encode()
            conn.sendall(send_packet)
        else:
            send_confirm_packet(1, "Invalid packet type", conn)
            time.sleep(1)
            conn.close()
            continue
        time.sleep(1)
        conn.close()
    except Exception as e:
        try:
            send_confirm_packet(1, str(e), current_conn)
            time.sleep(1)
            current_conn.close()
        except:
            pass
        continue