import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import psutil
import time
import threading


class NetworkMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("喵喵网络捕获器 Moe Network Catcher")
        self.root.geometry("1200x600")

        # 应用暗色主题
        self.apply_dark_theme()

        # 创建表格
        self.tree = ttk.Treeview(
            root, columns=("进程", "PID", "类型", "本地地址", "远程地址", "状态"), show="headings", style="Dark.Treeview"
        )
        self.tree.heading("进程", text="进程")
        self.tree.heading("PID", text="PID")
        self.tree.heading("类型", text="类型")
        self.tree.heading("本地地址", text="本地地址")
        self.tree.heading("远程地址", text="远程地址")
        self.tree.heading("状态", text="状态")
        self.tree.pack(fill=tk.BOTH, expand=True)

        # 绑定右键菜单
        self.tree.bind("<Button-3>", self.show_context_menu)

        # 创建右键菜单
        self.context_menu = tk.Menu(root, tearoff=0, bg="#333333", fg="white", activebackground="#555555", activeforeground="white")
        self.context_menu.add_command(label="终止进程", command=self.kill_process)
        self.context_menu.add_command(label="复制参数", command=self.copy_process_info)

        # 控制刷新状态的标志
        self.refresh_flag = True

        # 启动刷新线程
        self.update_data_thread = threading.Thread(target=self.refresh_data_periodically, daemon=True)
        self.update_data_thread.start()

    def apply_dark_theme(self):
        """应用暗色主题"""
        style = ttk.Style()
        style.theme_use("default")
        style.configure(
            "Dark.Treeview",
            background="#222222",
            foreground="white",
            rowheight=25,
            fieldbackground="#222222",
            bordercolor="#444444",
            borderwidth=1,
        )
        style.map("Dark.Treeview", background=[("selected", "#555555")], foreground=[("selected", "white")])

    def get_process_name(self, pid):
        """获取进程名"""
        try:
            process = psutil.Process(pid)
            return process.name()
        except psutil.NoSuchProcess:
            return "N/A"

    def parse_ip_and_port(self, ip_port_str):
        """解析IP地址和端口号"""
        if '[' in ip_port_str and ']' in ip_port_str:
            ip, port = f"[{ip_port_str.split('[')[1].split(']')[0]}]", ip_port_str.split(']')[1].strip(":")
        else:
            ip, port = ip_port_str.split(':')
        return ip, port

    def fetch_network_connections(self):
        """获取当前网络连接信息"""
        try:
            output = subprocess.check_output(['netstat', '-ano'], text=True)
            lines = output.splitlines()
            connections = {}

            for line in lines:
                if "TCP" in line or "UDP" in line:
                    parsed = line.split()
                    if len(parsed) >= 5:
                        protocol = parsed[0]
                        from_ip_port = parsed[1]
                        to_ip_port = parsed[2]
                        state = parsed[3] if protocol == "TCP" else "无"
                        pid = int(parsed[4] if protocol == "TCP" else parsed[3])

                        # 获取IP和端口
                        from_ip, local_port = self.parse_ip_and_port(from_ip_port)
                        to_ip, remote_port = self.parse_ip_and_port(to_ip_port)

                        process_name = self.get_process_name(pid)
                        connections[pid] = (process_name, pid, protocol, f"{from_ip}:{local_port}", f"{to_ip}:{remote_port}", state)

            return connections
        except subprocess.CalledProcessError as e:
            print(f"错误: {e}")
            return {}

    def refresh_data_periodically(self):
        """后台线程定期刷新数据"""
        while True:
            if self.refresh_flag:
                connections = self.fetch_network_connections()
                self.update_treeview(connections)
            time.sleep(5)

    def update_treeview(self, connections):
        """只更新新增和变动的数据行"""
        existing_pids = {self.tree.item(item)["values"][1] for item in self.tree.get_children()}
        new_pids = set(connections.keys())

        # 更新或插入新数据
        for pid, conn_info in connections.items():
            if pid in existing_pids:
                for item in self.tree.get_children():
                    if self.tree.item(item)["values"][1] == pid:
                        self.tree.item(item, values=conn_info)
            else:
                self.tree.insert("", "end", values=conn_info)

        # 删除已经不存在的进程
        for item in self.tree.get_children():
            if self.tree.item(item)["values"][1] not in new_pids:
                self.tree.delete(item)

    def show_context_menu(self, event):
        """显示右键菜单"""
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def kill_process(self):
        """终止选中的进程"""
        selected_item = self.tree.selection()
        if selected_item:
            pid = self.tree.item(selected_item)["values"][1]  # 获取PID
            self.refresh_flag = False  # 暂停刷新
            try:
                psutil.Process(pid).terminate()
                self.update_treeview(self.fetch_network_connections())  # 刷新数据
            except psutil.NoSuchProcess:
                messagebox.showerror("错误", "进程不存在，可能已被关闭")
            except psutil.AccessDenied:
                messagebox.showerror("错误", "权限不足，无法终止该进程")
            except Exception as e:
                messagebox.showerror("错误", f"无法终止进程: {e}")
            finally:
                self.refresh_flag = True  # 恢复刷新

    def copy_process_info(self):
        """复制进程参数到剪贴板"""
        selected_item = self.tree.selection()
        if selected_item:
            values = self.tree.item(selected_item)["values"]
            info = f"进程: {values[0]}\nPID: {values[1]}\n类型: {values[2]}\n本地地址: {values[3]}\n远程地址: {values[4]}\n状态: {values[5]}"
            self.root.clipboard_clear()
            self.root.clipboard_append(info)
            self.root.update()  # 确保剪贴板更新


def main():
    root = tk.Tk()
    app = NetworkMonitorApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
