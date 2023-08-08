import tkinter as tk
from tkinter import messagebox
import threading
import socket
import concurrent.futures


class PortScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Port Scanner")
        self.root.geometry("500x500")
        self.root.minsize(500, 500)
        self.root.maxsize(500, 500)

        self.host_label = tk.Label(root, text="Host:")
        self.host_label.pack()
        self.host_entry = tk.Entry(root)
        self.host_entry.pack()

        self.scan_type_var = tk.StringVar(value="all")
        self.scan_all_radiobutton = tk.Radiobutton(root, text="Scan All Ports", variable=self.scan_type_var, value="all", command=self.update_scan_type)
        self.scan_all_radiobutton.pack()
        self.scan_specific_radiobutton = tk.Radiobutton(root, text="Scan Specific Ports", variable=self.scan_type_var, value="specific", command=self.update_scan_type)
        self.scan_specific_radiobutton.pack()

        self.port_range_frame = tk.Frame(root)
        self.start_port_label = tk.Label(self.port_range_frame, text="Start Port:")
        self.start_port_label.pack(side=tk.LEFT)
        self.start_port_entry = tk.Entry(self.port_range_frame)
        self.start_port_entry.pack(side=tk.LEFT)
        self.end_port_label = tk.Label(self.port_range_frame, text="End Port:")
        self.end_port_label.pack(side=tk.LEFT)
        self.end_port_entry = tk.Entry(self.port_range_frame)
        self.end_port_entry.pack(side=tk.LEFT)

        self.specific_ports_label = tk.Label(root, text="Specific Ports (Comma-separated):")
        self.specific_ports_entry = tk.Entry(root)

        self.output_label = tk.Label(root, text="Output File:")
        self.output_label.pack()
        self.output_entry = tk.Entry(root)
        self.output_entry.pack()

        self.version_check_var = tk.IntVar()
        self.version_check_button = tk.Checkbutton(root, text="Service Version Detection",
                                                   variable=self.version_check_var)
        self.version_check_button.pack()


        self.scan_button = tk.Button(root, text="Scan", command=self.start_scan)
        self.scan_button.pack()

        self.result_text = tk.Text(root, height=10, width=40)
        self.result_text.pack()

        self.scan_thread = None
        self.update_scan_type()

    def update_scan_type(self):
        scan_type = self.scan_type_var.get()
        if scan_type == "all":
            self.port_range_frame.pack()
            self.specific_ports_label.pack_forget()
            self.specific_ports_entry.pack_forget()
            self.output_label.pack_forget()
            self.output_entry.pack_forget()
            self.scan_button.pack_forget()
            self.version_check_button.pack_forget()
            self.result_text.pack_forget()
            self.port_range_frame.pack()
            self.output_label.pack()
            self.output_entry.pack()
            self.version_check_button.pack()
            self.scan_button.pack()
            self.result_text.pack()
            
        elif scan_type == "specific":
            self.port_range_frame.pack_forget()
            self.specific_ports_label.pack()
            self.specific_ports_entry.pack()
            self.scan_button.pack_forget()
            self.version_check_button.pack_forget()
            self.result_text.pack_forget()
            
            self.output_entry.pack_forget()
            self.output_label.pack_forget()
            self.output_label.pack()
            self.output_entry.pack()
            
            
            # self.output_label.pack()
            # self.output_entry.pack()
            self.version_check_button.pack()
            self.scan_button.pack()
            self.result_text.pack()
    def start_scan(self):
        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showinfo("Scan in Progress", "A scan is already in progress.")
            return

        host = self.host_entry.get()
        
        if host == '':
            messagebox.showerror("Error","Enter the host")
            return
        try:
            socket.gethostbyname(host)
            socket.timeout(1)
            socket.gethostbyaddr(host)
            socket.timeout(1)
        except :
            messagebox.showerror("Error","cannot connect to the host")
            return
            
        
        
        
        else:
            scan_type = self.scan_type_var.get()
            if scan_type == "all":
                try:
                    start_port = int(self.start_port_entry.get())
                    end_port = int(self.end_port_entry.get())
                    if start_port < 0  :
                        start_port = start_port * -1
                    if end_port< 0   :
                        end_port = end_port * -1
                        
                except ValueError:
                    start_port = None
                    end_port = None
                    if start_port == None or end_port == None:

                        messagebox.showerror("Error","make sure you have Mentioned both start and end port")
                        return
                    else:
                        messagebox.showerror("Error", "Make sure to enter integer")
                    return
                
                if start_port > end_port:
                    temp = start_port
                    start_port=end_port
                    end_port=temp
                ports_to_scan = range(start_port, end_port + 1)
            elif scan_type == "specific":
                specific_ports = self.specific_ports_entry.get().split(",")
                specific_ports = [int(port.strip()) for port in specific_ports if port.strip()]
                if not specific_ports :
                    messagebox.showerror("Error", "Please provide at least one specific port.")
                    return
                ports_to_scan = specific_ports
            else:
                messagebox.showerror("Error", "Invalid scan type.")
                return

        output_file = self.output_entry.get()
        if output_file and not output_file.endswith(".txt"):
            messagebox.showerror("Error", "Invalid output file extension. Please use a .txt file.")
            return

        self.result_text.delete("1.0", tk.END)  

        self.result_text.insert(tk.END, "Scanning in progress...\n") 

        self.scan_thread = threading.Thread(target=self.scan_ports, args=(host, ports_to_scan, output_file))
        self.scan_thread.start()

    def scan_ports(self, host, ports, output_file):
        segment_size = 100  
        open_ports = []

        with concurrent.futures.ThreadPoolExecutor() as executor:
            segment_count = len(ports) // segment_size
            if len(ports) % segment_size != 0:
                segment_count += 1

            for i in range(segment_count):
                start = i * segment_size
                end = (i + 1) * segment_size
                segment_ports = ports[start:end]

                futures = [executor.submit(self.check_port, host, port) for port in segment_ports]

                for future in concurrent.futures.as_completed(futures):
                    port, result = future.result()
                    if result == 0:
                        self.result_text.insert(tk.END, f"Port {port} is open\n")
                        open_ports.append(port)
                   

        if open_ports:
            pass
        
        else:
            self.result_text.insert(tk.END, "No open ports found.")


        if self.version_check_var.get() == 1:
            self.result_text.insert(tk.END, "\nPerforming Service Version Detection...\n")
            self.perform_service_version_detection(host, open_ports)

        if output_file:
            self.save_output(output_file)
                
                
        self.result_text.insert(tk.END, "\nScanning finished\n")
        self.result_text.see(tk.END)
           


    def check_port(self, host, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            
            result = sock.connect_ex((host, port))
            sock.close()
            return port, result
      
        except socket.error:
            return port, None

    def perform_service_version_detection(self, host, open_ports):
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future_to_port = {executor.submit(self.detect_service_version, host, port): port for port in open_ports}
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    service_version = future.result()
                    self.result_text.insert(tk.END, f"Port {port}: {service_version}\n")
                except Exception as exc:
                    self.result_text.insert(tk.END, f"Port {port}: Error occurred during service version detection\n {str(exc)}")

    def detect_service_version(self, host, port):
        try:
            service_version = "Unknown"
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                sock.connect((host, port))
                sock.sendall(b"GET / HTTP/1.1\r\n\r\n")
                response = sock.recv(1024)
                if response:
                    service_version = response.decode().splitlines()[0]
            return service_version
        except socket.error:
            return "Unknown"

    def save_output(self, filename):
        try:
            if not filename.endswith(".txt"):
                messagebox.showerror("Error", "Invalid output file extension. Please use a .txt file.")
                return

            with open(filename, 'w') as file:
                file.write(self.result_text.get("1.0", tk.END))
            messagebox.showinfo("Success", f"Output saved to {filename}.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred while saving the output: {str(e)}")

if __name__ == "__main__":
        root = tk.Tk()
        port_scanner = PortScannerGUI(root)
        root.mainloop()
