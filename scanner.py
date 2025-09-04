#!/usr/bin/env python3
"""
Port Scanner (TCP & UDP) com GUI (PyQt5)
- Varre TCP (SYN se scapy/root disponível; fallback connect())
- Varre UDP (envia pacote UDP e tenta detectar ICMP unreachable se scapy disponível)
- Aceita um ou mais IPs (separados por vírgula) ou ranges/CIDR
- Interface com tabela, progresso e logs
- Requer Python 3.8+, recomenda-se rodar em Linux como root para varredura SYN/ICMP confiável
"""

import sys
import socket
import threading
import time
import ipaddress
from queue import Queue, Empty

# GUI
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QTableWidget, QTableWidgetItem, QPushButton, QLineEdit,
    QLabel, QTextEdit, QProgressBar, QComboBox, QMessageBox, QSpinBox
)
from PyQt5.QtCore import Qt, QTimer

# Optional: scapy for raw packet methods (SYN/ICMP)
USE_SCAPY = False
try:
    from scapy.all import IP, TCP, UDP, sr1, ICMP, conf
    conf.verb = 0
    USE_SCAPY = True
except Exception:
    USE_SCAPY = False

# ===========================
# Scanner worker functions
# ===========================

def expand_targets(target_str):
    """
    Receives comma-separated targets. Each target can be:
    - single IP: 192.168.0.5
    - CIDR: 192.168.0.0/28
    - range: 192.168.0.10-192.168.0.20
    Returns list of IP strings.
    """
    targets = []
    parts = [p.strip() for p in target_str.split(',') if p.strip()]
    for p in parts:
        try:
            if '/' in p:
                net = ipaddress.ip_network(p, strict=False)
                for ip in net.hosts():
                    targets.append(str(ip))
            elif '-' in p:
                a, b = p.split('-', 1)
                a = ipaddress.ip_address(a.strip())
                b = ipaddress.ip_address(b.strip())
                start = int(a)
                end = int(b)
                for i in range(start, end+1):
                    targets.append(str(ipaddress.ip_address(i)))
            else:
                # Tenta resolver como hostname primeiro, depois como IP
                try:
                    ip = socket.gethostbyname(p)
                    targets.append(ip)
                except socket.gaierror:
                    # Se falhar como hostname, tenta como IP direto
                    ipaddress.ip_address(p)  # Valida se é um IP válido
                    targets.append(p)
        except Exception as e:
            print(f"Target inválido '{p}': {e}")
            continue
    return sorted(set(targets))

def tcp_connect_scan(ip, port, timeout=1.0):
    """Fallback TCP connect scan using socket (works without root)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        s.close()
        return 'open'
    except socket.timeout:
        return 'filtered'
    except ConnectionRefusedError:
        return 'closed'
    except Exception:
        return 'filtered'

def tcp_syn_scan_scapy(ip, port, timeout=1.0):
    """SYN scan using scapy. Requires root and scapy available."""
    try:
        pkt = IP(dst=ip)/TCP(dport=port, flags='S')
        resp = sr1(pkt, timeout=timeout, verbose=0)
    except Exception:
        return 'filtered'
    if not resp:
        return 'filtered'
    if resp.haslayer(TCP):
        t = resp.getlayer(TCP)
        if t.flags & 0x12:  # SYN+ACK
            # Envia RST para fechar a conexão
            rst = IP(dst=ip)/TCP(dport=port, flags='R', seq=t.ack)
            try:
                sr1(rst, timeout=0.5, verbose=0)
            except Exception:
                pass
            return 'open'
        elif t.flags & 0x14:  # RST+ACK
            return 'closed'
    return 'filtered'

def udp_scan_scapy(ip, port, timeout=2.0):
    """UDP scan using scapy: send empty UDP and wait ICMP unreachable (port closed)."""
    try:
        pkt = IP(dst=ip)/UDP(dport=port)
        resp = sr1(pkt, timeout=timeout, verbose=0)
    except Exception:
        return 'open|filtered'
    if not resp:
        return 'open|filtered'
    if resp.haslayer(ICMP):
        icmp = resp.getlayer(ICMP)
        if int(icmp.type) == 3 and int(icmp.code) in (1,2,3,9,10,13):
            return 'closed'
    return 'open|filtered'

def udp_scan_socket(ip, port, timeout=2.0):
    """Simple UDP probe using sockets."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(b'', (ip, port))
        data, _ = s.recvfrom(1024)
        if data:
            return 'open'
    except socket.timeout:
        return 'open|filtered'
    except ConnectionRefusedError:
        return 'closed'
    except Exception:
        return 'open|filtered'
    finally:
        try:
            s.close()
        except:
            pass
    return 'open|filtered'

# Worker thread
def worker_scan(queue, results_q, stop_event, use_scapy=USE_SCAPY, timeout_tcp=1.0, timeout_udp=2.0):
    while not stop_event.is_set():
        try:
            ip, port, proto = queue.get_nowait()
        except Empty:
            break
        
        state = 'unknown'
        try:
            if proto == 'tcp':
                if use_scapy:
                    state = tcp_syn_scan_scapy(ip, port, timeout=timeout_tcp)
                else:
                    state = tcp_connect_scan(ip, port, timeout=timeout_tcp)
            elif proto == 'udp':
                if use_scapy:
                    state = udp_scan_scapy(ip, port, timeout=timeout_udp)
                else:
                    state = udp_scan_socket(ip, port, timeout=timeout_udp)
        except Exception as e:
            state = f'err:{e}'
        
        results_q.put((ip, port, proto.upper(), state))
        queue.task_done()

# ===========================
# GUI Application
# ===========================

class ScannerGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Port Scanner (TCP & UDP) - Simple")
        self.resize(900, 600)
        self._threads = []
        self._stop_event = threading.Event()
        self._results_q = Queue()
        self._scan_queue = Queue()

        # Layouts
        layout = QVBoxLayout()
        form = QHBoxLayout()
        form.addWidget(QLabel("Targets (IP,CIDR,range like 192.168.1.1-192.168.1.50):"))
        self.targets_input = QLineEdit("127.0.0.1")
        form.addWidget(self.targets_input)
        form.addWidget(QLabel("Ports (ex: 22,80,443 or 1-1024):"))
        self.ports_input = QLineEdit("22,80,443,53,161")
        form.addWidget(self.ports_input)
        form.addWidget(QLabel("Mode:"))
        self.mode_cb = QComboBox()
        self.mode_cb.addItems(["TCP", "UDP", "BOTH"])
        form.addWidget(self.mode_cb)
        form.addWidget(QLabel("Threads:"))
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 200)
        self.threads_spin.setValue(100)
        form.addWidget(self.threads_spin)
        layout.addLayout(form)

        # Buttons
        btns = QHBoxLayout()
        self.start_btn = QPushButton("Start Scan")
        self.start_btn.clicked.connect(self.start_scan)
        btns.addWidget(self.start_btn)
        self.stop_btn = QPushButton("Stop Scan")
        self.stop_btn.clicked.connect(self.stop_scan)
        btns.addWidget(self.stop_btn)
        self.clear_btn = QPushButton("Clear Results")
        self.clear_btn.clicked.connect(self.clear_results)
        btns.addWidget(self.clear_btn)
        self.info_btn = QPushButton("Info")
        self.info_btn.clicked.connect(self.show_info)
        btns.addWidget(self.info_btn)
        layout.addLayout(btns)

        # Table
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["IP", "Port", "Proto", "State", "Timestamp"])
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table)

        # Progress & log
        bottom = QHBoxLayout()
        self.progress = QProgressBar()
        bottom.addWidget(self.progress)
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        bottom.addWidget(self.log)
        layout.addLayout(bottom)

        self.setLayout(layout)

        # Timer
        self.timer = QTimer()
        self.timer.setInterval(200)
        self.timer.timeout.connect(self.poll_results)
        self.timer.start()

    def append_log(self, text):
        self.log.append(text)

    def parse_ports(self, s):
        s = s.strip()
        ports = set()
        parts = [p.strip() for p in s.split(',') if p.strip()]
        for p in parts:
            if '-' in p:
                a, b = p.split('-', 1)
                try:
                    for x in range(int(a), int(b)+1):
                        if 0 < x <= 65535:
                            ports.add(x)
                except Exception:
                    continue
            else:
                try:
                    x = int(p)
                    if 0 < x <= 65535:
                        ports.add(x)
                except Exception:
                    continue
        return sorted(ports)

    def start_scan(self):
        if self._threads:
            QMessageBox.warning(self, "Já em execução", "Já existe uma varredura em execução.")
            return
        
        targets_raw = self.targets_input.text().strip()
        if not targets_raw:
            QMessageBox.warning(self, "Erro", "Informe targets válidos.")
            return
        
        try:
            targets = expand_targets(targets_raw)
        except Exception as e:
            QMessageBox.warning(self, "Erro", f"Erro ao processar targets: {e}")
            return
            
        if not targets:
            QMessageBox.warning(self, "Erro", "Nenhum alvo válido encontrado.")
            return
            
        ports = self.parse_ports(self.ports_input.text())
        if not ports:
            QMessageBox.warning(self, "Erro", "Informe portas válidas.")
            return
            
        mode = self.mode_cb.currentText()
        threads_count = self.threads_spin.value()
        use_scapy = USE_SCAPY
        
        if use_scapy:
            self.append_log("scapy disponível: usando métodos raw (SYN/ICMP).")
        else:
            self.append_log("scapy NÃO encontrado: usando métodos socket.")

        self._scan_queue = Queue()
        total_tasks = 0
        
        for ip in targets:
            if mode in ("TCP", "BOTH"):
                for p in ports:
                    self._scan_queue.put((ip, p, "tcp"))
                    total_tasks += 1
            if mode in ("UDP", "BOTH"):
                for p in ports:
                    self._scan_queue.put((ip, p, "udp"))
                    total_tasks += 1

        if total_tasks == 0:
            QMessageBox.warning(self, "Erro", "Nenhuma tarefa de varredura criada.")
            return

        self.progress.setMaximum(total_tasks)
        self.progress.setValue(0)
        self.append_log(
            f"Iniciando varredura: {len(targets)} alvo(s), {len(ports)} porta(s) => {total_tasks} tarefas"
        )
        self._stop_event = threading.Event()
        self._results_q = Queue()

        self._threads = []
        for i in range(threads_count):
            t = threading.Thread(
                target=worker_scan,
                args=(self._scan_queue, self._results_q, self._stop_event, use_scapy)
            )
            t.daemon = True
            t.start()
            self._threads.append(t)

    def poll_results(self):
        updated = False
        while True:
            try:
                ip, port, proto, state = self._results_q.get_nowait()
            except Empty:
                break
            updated = True
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(str(ip)))
            self.table.setItem(row, 1, QTableWidgetItem(str(port)))
            self.table.setItem(row, 2, QTableWidgetItem(str(proto)))
            self.table.setItem(row, 3, QTableWidgetItem(str(state)))
            self.table.setItem(row, 4, QTableWidgetItem(time.strftime("%Y-%m-%d %H:%M:%S")))

            val = self.progress.value() + 1
            if val <= self.progress.maximum():
                self.progress.setValue(val)

            # Color coding based on state
            if 'open' in state and not state.startswith('err:'):
                color = Qt.green
            elif 'closed' in state and not state.startswith('err:'):
                color = Qt.red
            elif 'filtered' in state and not state.startswith('err:'):
                color = Qt.yellow
            else:
                color = Qt.white
                
            for c in range(self.table.columnCount()):
                self.table.item(row, c).setBackground(color)

        if updated and self._threads and all(not t.is_alive() for t in self._threads):
            self.append_log("Varredura finalizada.")
            self._threads = []

    def stop_scan(self):
        if not self._threads:
            self.append_log("Nenhuma varredura ativa.")
            return
        self._stop_event.set()
        self.append_log("Parando varredura...")
        for t in self._threads:
            t.join(timeout=1.0)
        self._threads = []
        self.append_log("Varredura parada.")

    def clear_results(self):
        self.table.setRowCount(0)
        self.progress.setValue(0)
        self.log.clear()

    def show_info(self):
        info = (
            "Instruções:\n"
            "- Para usar SYN scan, execute como root e instale scapy: pip install scapy\n"
            "- Caso contrário, usa TCP connect e UDP socket.\n"
            "- Alvos: IPs separados, ranges (a-b) e CIDR aceitos.\n"
            "- Modos: TCP, UDP, BOTH.\n"
            "\nLimitações:\n"
            "- UDP muitas vezes retorna 'open|filtered' por falta de resposta.\n"
            "- Alguns hosts bloqueiam tráfego RAW."
        )
        QMessageBox.information(self, "Info", info)

def main():
    app = QApplication(sys.argv)
    gui = ScannerGUI()
    gui.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
