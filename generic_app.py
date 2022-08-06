import tkinter as tk
from tkinter import filedialog
import tkinter.scrolledtext as st
import socket
import time
import rsa
import hashlib
import pickle
import json

class GenericApplication:
    def __init__(self, server_ip, server_port, is_server=False):
        """
        Creates application. If is_server is True, additional managment capabilities are included

        :param is_server (bool): True if server application is to be created
        :param server_ip (str): IP address of server
        :param server_port (int): port of server
        :return: main 
        """

        self.is_server = is_server
        self.server_ip = server_ip
        self.server_port = server_port
        self.apps = []
        self.procs = []
        self.main = None
        self.result = None
        self.socket = None
        self.current_key = None
        self.title = "Manage Remote App" if self.is_server else "Remote App"

        self.magic = None

        with open("magic.txt", "rb") as f:
            self.magic = f.read()

    def initiate_connection(self):
        """
        Initiates connection to server.
        """
        
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.server_ip, self.server_port))

        com_type = 5
        packet = b""
        packet += com_type.to_bytes(2, byteorder="big")
        self.socket.sendall(packet)

        recv_type = int.from_bytes(self.socket.recv(2), byteorder="big")

        if recv_type != 2:
            self.socket.close()
            print("Error: Server did not respond with correct type")
            print(recv_type)
            print("Error: Failed to Connect to Server. Attempting again...")
            self.initiate_connection()
            return
        
        recv_len = int.from_bytes(self.socket.recv(4), byteorder="big")
        recv_md5 = self.socket.recv(16)
        recv_key = self.socket.recv(recv_len)

        if hashlib.md5(recv_key).digest() != recv_md5:
            print("Error: Server sent invalid key")
            self.socket.close()
            print("Error: Failed to Connect to Server. Attempting again...")
            self.initiate_connection()
            return

        self.current_key = pickle.loads(recv_key)

    def send_packet(self, type, data):
        """
        Sends packet to server.
        """

        packet = b""
        self.initiate_connection()
        packet += rsa.encrypt(self.magic, self.current_key)
        packet += type.to_bytes(2, byteorder="big")
        packet += data

        self.socket.sendall(packet)

    def update_result(self, result):
        """Updates result text field with result of last action

        Args:
            result (str): result of last action
        """

        self.result = result

    def popup(self, title, body):
        """ Creates popup window with title and body.

        Args:
            title (str): title of popup window
            body (str): body of popup window
        """
        popup = tk.Toplevel(self.main, bg="#aaaaaa")
        popup.title(title)
        popup.geometry("320x250")
        popup.grab_set()

        # Input field for path to application
        text_area = st.ScrolledText(popup, height=10)
        text_area.insert(tk.INSERT, body)
        text_area.configure(state ='disabled')
        text_area.pack(side=tk.TOP, expand=False, fill=tk.X, pady=10, padx=10, anchor=tk.NW)

        # Cancel and OK buttons
        buttons_frame = tk.Frame(popup, bg="#aaaaaa")
        ok_button = tk.Button(buttons_frame, text="OK", font=('Arial', 12), command=popup.destroy)
        
        ok_button.pack(side=tk.RIGHT, expand=True, fill=tk.BOTH, padx=20)
        buttons_frame.pack(side=tk.TOP, expand=False, pady=10, anchor=tk.SE)

    def confirm(self, body):
        """Confirms action described by body

        Args:
            body (str): body describing action to confirm

        Returns:
            Tk.Toplevel: window with confirmation
        """

        confirm_window = tk.Toplevel(self.main, bg="#aaaaaa")
        confirm_window.title("Confirm")
        confirm_window.geometry("320x250")
        confirm_window.grab_set()

        # Input field for path to application
        text_area = st.ScrolledText(confirm_window, height=10)
        text_area.insert(tk.INSERT, body)
        text_area.configure(state ='disabled')
        text_area.pack(side=tk.TOP, expand=False, fill=tk.X, pady=10, padx=10, anchor=tk.NW)

        # Yes and No buttons

        buttons_frame = tk.Frame(confirm_window, bg="#aaaaaa")
        yes_button = tk.Button(buttons_frame, text="Yes", font=('Arial', 12), command=lambda: self.update_result(True) or confirm_window.destroy() or confirm_window.grab_release())
        no_button = tk.Button(buttons_frame, text="No", font=('Arial', 12), command=lambda: self.update_result(False) or confirm_window.destroy() or confirm_window.grab_release())

        yes_button.pack(side=tk.RIGHT, expand=True, fill=tk.BOTH, padx=20)
        no_button.pack(side=tk.RIGHT, expand=True, fill=tk.BOTH, padx=20)
        buttons_frame.pack(side=tk.TOP, expand=False, pady=1)

        return confirm_window

    def get_apps(self):
        """
        Sends request to server to get list of applications.

        :return: list of applications
        """
        
        self.send_packet(0, b"")

        recv_type = int.from_bytes(self.socket.recv(2), byteorder="big")

        if recv_type != 3:
            self.socket.close()
            print("Error: Failed to Connect to Server. Attempting again...")
            return self.get_apps()
        
        num_apps = int.from_bytes(self.socket.recv(2), byteorder="big")
        apps = []

        for _ in range(num_apps):
            name_len = int.from_bytes(self.socket.recv(2), byteorder="big")
            id = int.from_bytes(self.socket.recv(2), byteorder="big")
            name = self.socket.recv(name_len).decode("utf-8")
            apps.append((name, id))
        
        self.socket.close()

        return apps
    
    def get_confirmation(self):
        """
        Waits for confirmation from server.
        """

        recv_type = int.from_bytes(self.socket.recv(2), byteorder="big")

        if recv_type != 0:
            self.socket.close()
            print("Error: Failed to Connect to Server. Attempting again...")
            return False

        status = int.from_bytes(self.socket.recv(2), byteorder="big")
        data_len = int.from_bytes(self.socket.recv(4), byteorder="big")
        data = self.socket.recv(data_len)

        if status != 0:
            self.socket.close()
            self.popup("Error", f'Exit Code {status}:\n{data.decode("utf-8")}')
            print("Error: Failed to Connect to Server. Attempting again...")
            print(data.decode("utf-8"))
            return False
        
        return True

    def start_app(self, selection):
        """Starts application selected

        Args:
            selection (Tuple): selected application
        """

        if len(selection) == 0:
            self.popup("error", "No application selected")
            return
        
        id = self.apps[selection[0]][1]

        data = id.to_bytes(2, byteorder="big")
        
        self.send_packet(2, data)
        

        if not self.get_confirmation():
            self.socket.close()
            return

        self.socket.close()
        self.popup("success", "Application started")
        pass

    def remove_app(self, selection):
        """Removes application selected

        Args:
            selection (Tuple): selected application
        """

        if len(selection) == 0:
            self.popup("error", "No application selected")
            return
        
        id = self.apps[selection[0]][1]

        confirm_window = self.confirm("Are you sure you want to remove application " + self.apps[selection[0]][0] + "?")

        self.main.wait_window(confirm_window)

        with open("./data.json", "r") as f:
            data = json.load(f)
        
        if id not in data["apps"]:
            self.popup("error", "Application not found")
            return
        
        del data["apps"][id]

        with open("./data.json", "w") as f:
            json.dump(data, f)

        if self.result:
            self.popup("success", "Application removed")

        self.result = None

    def stop_process(self, selection, window):
        """Stops process selected

        Args:
            selection (Tuple): selected process
        """

        if len(selection) == 0:
            self.popup("error", "No process selected")
            return
        
        id = self.procs[selection[0]][2]

        data = id.to_bytes(4, byteorder="big")
        self.send_packet(3, data)

        if not self.get_confirmation():
            self.socket.close()
            self.stop_process(selection)
            return

        self.socket.close()
        self.popup("success", "Process stopped")
        self.processes_window()
        pass

    def save_log_ok(self, selection, log_path):
        """Saves log of process selected to log_path

        Args:
            selection (Tuple): selected process
            log_path (str): path to save log
        """

        if len(selection) == 0:
            self.popup("error", "No process selected")
            return

        id = self.procs[selection[0]][2]

        data = id.to_bytes(4, byteorder="big")
        print(data)

        self.send_packet(4, data)

        recv_type = int.from_bytes(self.socket.recv(2), byteorder="big")

        if recv_type != 1:
            self.socket.close()
            print("Error: Failed to Connect to Server. Attempting again...")
            return self.save_log_ok(selection, log_path)

        data_len = int.from_bytes(self.socket.recv(4), byteorder="big")
        data = self.socket.recv(data_len).decode("utf-8")

        with open(log_path, "w") as f:
            f.write(data)

        self.socket.close()
        self.popup("success", "Log saved")
        pass

    def save_log_window(self, selection):
        """Window that handles log saving"""

        if len(selection) == 0:
            self.popup("error", "No process selected")
            return

        log_window = tk.Toplevel(self.main, bg="#aaaaaa")
        log_window.title("Save Log")
        log_window.geometry("320x170")

        # Input field for path to log file
        path_frame = tk.Frame(log_window, bg="#aaaaaa")
        path_label = tk.Label(path_frame, text="Path:", font=('Arial', 12), bg="#aaaaaa")
        path_entry = tk.Entry(path_frame, font=('Arial', 12))
        browse_button = tk.Button(path_frame, text="Browse", font=('Arial', 12), command=lambda: self.browse(path_entry, suffix=f"/{self.procs[selection[0]][0]}_{time.time()}.log", directory=True))

        path_label.pack(side=tk.TOP, anchor=tk.NW)
        path_entry.pack(side=tk.LEFT, expand=False, fill=tk.X, pady=10)
        browse_button.pack(side=tk.LEFT, expand=True, fill=tk.BOTH, padx=20, pady=10)
        path_frame.pack(side=tk.TOP, expand=False, pady=10, padx=10, anchor=tk.NW)

        # Cancel and OK buttons
        buttons_frame = tk.Frame(log_window, bg="#aaaaaa")
        cancel_button = tk.Button(buttons_frame, text="Cancel", font=('Arial', 12), command=log_window.destroy)
        ok_button = tk.Button(buttons_frame, text="OK", font=('Arial', 12), command=lambda: self.save_log_ok(selection, path_entry.get()) or log_window.destroy())
        
        cancel_button.pack(side=tk.RIGHT, expand=True, fill=tk.BOTH, padx=20)
        ok_button.pack(side=tk.RIGHT, expand=True, fill=tk.BOTH, padx=20)
        buttons_frame.pack(side=tk.TOP, expand=False, pady=10, anchor=tk.SE)

    def browse(self, text_entry=None, suffix="", directory=False):
        """Allows user to select a file and places context in the provided text entry

        Args:
            text_entry (Tkinter.Entry): _description_. Defaults to None.
            suffix (str): Name of file or extension placed after selected path. Defaults to "".
            directory (bool): If True, allows user to select a directory. Defaults to False.
        """

        if not directory:
            self.result = filedialog.askopenfilename(initialdir = "/", title = "Select a File")
        else:
            self.result = filedialog.askdirectory(initialdir = "/", title = "Select a Directory")

        if text_entry is not None:
            text_entry.delete(0, tk.END)
            text_entry.insert(0, self.result+suffix)

    def add_or_edit_application_ok(self, path, name, add=True, appid=None):
        """Adds or edits application based on add and appid

        Args:
            path (str): path to application
            name (str): name of application
            add (bool): if True, adds application. If False, edits application
            appid (int): id of application to edit
        """
        
        if add:
            with open("./data.json", "r") as f:
                data = json.load(f)
            
            data["apps"][len(data["apps"])] = {"path": path, "name": name}
        else:
            with open("./data.json", "r") as f:
                data = json.load(f)
            
            data["apps"][f"{appid}"] = {"path": path, "name": name}
        
        with open("./data.json", "w") as f:
            json.dump(data, f)
        
        pass

    def add_or_edit_application(self, add=True, appid=None):
        """
        Creates window to add or adit an application.
        """

        cur_name = ""
        cur_path = ""

        if not add:
            with open("./data.json", "r") as f:
                data = json.load(f)
            cur_name = data["apps"][f"{appid}"]["name"]
            cur_path = data["apps"][f"{appid}"]["path"]


        popup = tk.Toplevel(self.main, bg="#aaaaaa")
        popup.title("Add Application" if add else "Edit Application")
        popup.geometry("320x250")
        popup.grab_set()

        # Input field for path to application
        path_frame = tk.Frame(popup, bg="#aaaaaa")
        path_label = tk.Label(path_frame, text="Path:", font=('Arial', 12), bg="#aaaaaa")
        path_entry = tk.Entry(path_frame, font=('Arial', 12))
        path_entry.insert(tk.END, cur_path)
        browse_button = tk.Button(path_frame, text="Browse", font=('Arial', 12), command=lambda: self.browse(path_entry))

        path_label.pack(side=tk.TOP, anchor=tk.NW)
        path_entry.pack(side=tk.LEFT, expand=False, fill=tk.X, pady=10)
        browse_button.pack(side=tk.LEFT, expand=True, fill=tk.BOTH, padx=20, pady=10)
        path_frame.pack(side=tk.TOP, expand=False, pady=10, padx=10, anchor=tk.NW)

        # Input field for name of application
        name_frame = tk.Frame(popup, bg="#aaaaaa")
        name_label = tk.Label(name_frame, text="Name:", font=('Arial', 12), bg="#aaaaaa")
        name_entry = tk.Entry(name_frame, font=('Arial', 12))
        name_entry.insert(tk.END, cur_name)

        name_label.pack(side=tk.TOP, anchor=tk.NW)
        name_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, pady=10)

        name_frame.pack(side=tk.TOP , expand=False, pady=10, padx=10, anchor=tk.NW)

        # Cancel and OK buttons
        buttons_frame = tk.Frame(popup, bg="#aaaaaa")
        cancel_button = tk.Button(buttons_frame, text="Cancel", font=('Arial', 12), command=popup.destroy)

        add_lambda = command=lambda: self.add_or_edit_application_ok(path_entry.get(), name_entry.get()) or popup.destroy() or self.main.destroy() or self.run_application()
        edit_lambda = command=lambda: self.add_or_edit_application_ok(path_entry.get(), name_entry.get(), add=False, appid=appid) or popup.destroy() or self.main.destroy() or self.run_application()

        ok_button = tk.Button(buttons_frame, text="OK", font=('Arial', 12), 
                            command=add_lambda if add else edit_lambda)
        
        cancel_button.pack(side=tk.RIGHT, expand=True, fill=tk.BOTH, padx=20)
        ok_button.pack(side=tk.RIGHT, expand=True, fill=tk.BOTH, padx=20)
        buttons_frame.pack(side=tk.TOP, expand=False, pady=10, anchor=tk.SE)

    def edit_application_helper(self, selection):
        """Edits application entry

        Args:
            selection (Tuple): selected application
        """

        if len(selection) == 0:
            self.popup("error", "No application selected")
            return
        
        id = self.apps[selection[0]][1]

        self.add_or_edit_application(False, id)

    def run_application(self):
        """
        Creates main screen of application.
        """

        main = tk.Tk()
        main["bg"] = "#aaaaaa"
        self.main = main
        main.title(self.title)
        main.geometry("500x400")
        self.apps = self.get_apps()


        # Create listbox to display applications
        listbox_frame = tk.Frame(main, height=300, width=200, bg="#aaaaaa")
        listbox_frame.propagate(False)
        
        apps_title = tk.Label(listbox_frame, text="Applications:", font=('Arial', 12), bg="#aaaaaa")

        scrollbar = tk.Scrollbar(listbox_frame, orient=tk.VERTICAL, troughcolor="blue")
        apps_list = tk.Listbox(listbox_frame, yscrollcommand=scrollbar.set)

        for app in self.apps:
            apps_list.insert(tk.END, app[0])

        
        apps_title.pack(side=tk.TOP, anchor=tk.NW)

        apps_list.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)
        scrollbar.pack(side=tk.LEFT, expand=True, fill=tk.Y)
        scrollbar.config(command=apps_list.yview)

        listbox_frame.pack(side=tk.LEFT, expand=False, padx=20)

        # Creates buttons to manage applications

        button_frame = tk.Frame(main, height=300, width=200, bg="#aaaaaa")
        button_frame.propagate(False)

        add_application_button = tk.Button(button_frame, text="Add", command=self.add_or_edit_application, font=('Arial', 12))
        start_application_button = tk.Button(button_frame, text="Start", command=lambda: self.start_app(apps_list.curselection()), font=('Arial', 12))
        edit_application_button = tk.Button(button_frame, text="Edit", font=('Arial', 12), command=lambda: self.edit_application_helper(apps_list.curselection()))
        remove_application_button = tk.Button(button_frame, text="Remove", command=lambda: self.remove_app(apps_list.curselection()), font=('Arial', 12))
        current_processes_button = tk.Button(button_frame, text="Current Processes", command=self.processes_window or self.main.deiconify(), font=('Arial', 12))

        if self.is_server:
            add_application_button.pack(side=tk.TOP, pady=10)
            edit_application_button.pack(side=tk.TOP, pady=10)
            remove_application_button.pack(side=tk.TOP, pady=10)
        
        start_application_button.pack(side=tk.TOP, pady=10)
        current_processes_button.pack(side=tk.TOP, pady=10)

        button_frame.pack(side=tk.RIGHT, expand=False, padx=20)

        main.mainloop()

    def get_processes(self):
        """
        Gets current processes.
        """
        
        self.send_packet(1, b"")

        recv_type = int.from_bytes(self.socket.recv(2), byteorder="big")

        if recv_type != 4:
            self.socket.close()
            self.popup("error", "Error getting processes")
            self.get_processes()
            return

        num_procs = int.from_bytes(self.socket.recv(2), byteorder="big")
        procs = []

        for _ in range(num_procs):
            name_len = int.from_bytes(self.socket.recv(2), byteorder="big")
            status = int.from_bytes(self.socket.recv(2), byteorder="big")
            pid = int.from_bytes(self.socket.recv(4), byteorder="big")
            name = self.socket.recv(name_len).decode("utf-8")
            procs.append((name, status, pid))
        
        return procs

    def processes_window(self): 
        self.main.destroy()

        processes_window = tk.Tk()
        processes_window["bg"] = "#aaaaaa"
        processes_window.geometry("500x400")
        processes_window.title("Current Processes")
        self.main = processes_window

        self.procs = self.get_processes()

        # Create listbox to display Processes
        listbox_frame = tk.Frame(processes_window, height=300, width=200, bg="#aaaaaa")
        listbox_frame.propagate(False)
        
        procs_title = tk.Label(listbox_frame, text="Processes:", font=('Arial', 12), bg="#aaaaaa")

        scrollbar = tk.Scrollbar(listbox_frame, orient=tk.VERTICAL, troughcolor="blue")
        procs_list = tk.Listbox(listbox_frame, yscrollcommand=scrollbar.set)

        for proc in self.procs:
            procs_list.insert(tk.END, f"{proc[0]} ({proc[2]}): {'OK' if proc[1] == 0 else 'ERROR'}")

        
        procs_title.pack(side=tk.TOP, anchor=tk.NW)

        procs_list.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)
        scrollbar.pack(side=tk.LEFT, expand=True, fill=tk.Y)
        scrollbar.config(command=procs_list.yview)

        listbox_frame.pack(side=tk.LEFT, expand=False, padx=20)

        # Creates buttons to manage processes

        button_frame = tk.Frame(processes_window, height=300, width=200, bg="#aaaaaa")
        button_frame.propagate(False)

        back_button = tk.Button(button_frame, text="Back", command=lambda: processes_window.destroy() or self.run_application(), font=('Arial', 12))
        save_log_button = tk.Button(button_frame, text="Save Log", command=lambda: self.save_log_window(procs_list.curselection()), font=('Arial', 12))
        stop_button = tk.Button(button_frame, text="Stop", command=lambda: self.stop_process(procs_list.curselection(), processes_window), font=('Arial', 12))

        back_button.pack(side=tk.TOP, pady=10)
        save_log_button.pack(side=tk.TOP, pady=10)
        stop_button.pack(side=tk.TOP, pady=10)

        button_frame.pack(side=tk.RIGHT, expand=False, padx=20)

        return processes_window