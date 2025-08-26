# MalduarkAnaly.py - Ferramenta de Análise de Malware em Ambiente Isolado (2025)
# Criado por Hygark (2025)
# Descrição: Ferramenta para análise estática e dinâmica de arquivos suspeitos, com monitoramento de processos, rede, chamadas de sistema, integração com VirusTotal, relatórios em JSON/CSV/PDF/HTML e GUI Tkinter.

import os
import time
import threading
import subprocess
import psutil
import pefile
import hashlib
import requests
from scapy.all import sniff, IP, TCP, UDP
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table
from reportlab.lib.styles import getSampleStyleSheet
import json
import csv
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from tkinterweb.htmlwidgets import HtmlFrame
import logging.handlers

# Configurações personalizáveis
Settings = {
    'FilePath': '',  # Caminho do arquivo a ser analisado
    'MonitorDuration': 30,  # Duração do monitoramento (segundos)
    'VirusTotalApiKey': '',  # Chave da API do VirusTotal
    'LogFile': 'logs/malduark_analy.log',  # Arquivo de log
    'LogWebhook': '',  # URL de webhook
    'SyslogServer': '',  # Servidor Syslog
    'SyslogPort': 514,  # Porta Syslog
    'ReportDir': 'reports/',  # Diretório para relatórios
    'ExportJSON': True,  # Exportar em JSON
    'ExportCSV': True,  # Exportar em CSV
    'ExportPDF': True,  # Exportar em PDF
    'ExportHTML': True,  # Exportar em HTML
    'SuspiciousIPs': ['127.0.0.1', '169.254.169.254'],  # IPs suspeitos para monitoramento
    'SuspiciousCalls': ['CreateFile', 'Connect', 'RegCreateKey'],  # Chamadas de sistema suspeitas
    'NetworkInterface': 'eth0',  # Interface de rede para monitoramento
}

# Estado do script
ScriptState = {
    'IsRunning': False,
    'AnalysisResults': {
        'Static': {},
        'Dynamic': {'cpu': [], 'memory': [], 'network': [], 'calls': []},
        'VirusTotal': {},
    },
    'TotalIssues': 0,
}

# Configuração de logging Syslog
syslog_handler = None
if Settings['SyslogServer']:
    syslog_handler = logging.handlers.SysLogHandler(address=(Settings['SyslogServer'], Settings['SyslogPort']))
    syslog_handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(name)s: %(levelname)s %(message)s')
    syslog_handler.setFormatter(formatter)
    logging.getLogger('').addHandler(syslog_handler)

# Função para enviar logs
def log_message(level, message):
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    log_entry = f"[{level}] [{timestamp}] {message}"
    print(log_entry)
    
    os.makedirs(os.path.dirname(Settings['LogFile']), exist_ok=True)
    with open(Settings['LogFile'], 'a') as f:
        f.write(log_entry + '\n')
    
    if Settings['LogWebhook']:
        try:
            requests.post(Settings['LogWebhook'], json={'content': log_entry}, timeout=5)
        except Exception as e:
            print(f"[ERRO] Falha ao enviar log para webhook: {e}")
    
    if syslog_handler:
        logging.getLogger('').log(
            {'INFO': logging.INFO, 'AVISO': logging.WARNING, 'CRÍTICO': logging.CRITICAL, 'ERRO': logging.ERROR}.get(level, logging.INFO),
            log_entry
        )

# Função para análise estática
def static_analysis(file_path):
    try:
        pe = pefile.PE(file_path)
        static_data = {
            'File': os.path.basename(file_path),
            'EntryPoint': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            'ImageBase': hex(pe.OPTIONAL_HEADER.ImageBase),
            'Sections': [s.Name.decode().strip('\x00') for s in pe.sections],
            'Imports': [],
            'MD5': hashlib.md5(open(file_path, 'rb').read()).hexdigest(),
            'SHA256': hashlib.sha256(open(file_path, 'rb').read()).hexdigest(),
        }
        
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        static_data['Imports'].append(imp.name.decode())
        
        suspicious_imports = [imp for imp in static_data['Imports'] if any(call in imp for call in Settings['SuspiciousCalls'])]
        if suspicious_imports:
            ScriptState['TotalIssues'] += len(suspicious_imports)
            for imp in suspicious_imports:
                ScriptState['AnalysisResults']['Static']['SuspiciousImports'] = ScriptState['AnalysisResults']['Static'].get('SuspiciousImports', []) + [(imp, 'Importação suspeita detectada')]
                log_message('AVISO', f'Importação suspeita detectada: {imp}')
        
        ScriptState['AnalysisResults']['Static'] = static_data
        log_message('INFO', f'Análise estática concluída para {file_path}')
    except Exception as e:
        log_message('ERRO', f'Erro na análise estática de {file_path}: {e}')

# Função para análise dinâmica
def dynamic_analysis(file_path, duration):
    try:
        proc = subprocess.Popen(file_path, shell=True)
        ps_proc = psutil.Process(proc.pid)
        start_time = time.time()
        
        while time.time() - start_time < duration and ps_proc.is_running():
            cpu = ps_proc.cpu_percent(interval=0.1)
            memory = ps_proc.memory_info().rss / 1024**2  # MB
            ScriptState['AnalysisResults']['Dynamic']['cpu'].append(cpu)
            ScriptState['AnalysisResults']['Dynamic']['memory'].append(memory)
            
            if cpu > 80 or memory > 500:  # Limites arbitrários para exemplo
                ScriptState['AnalysisResults']['Dynamic']['calls'].append(('HighResourceUsage', f'CPU: {cpu:.2f}%, Memória: {memory:.2f} MB'))
                ScriptState['TotalIssues'] += 1
                log_message('AVISO', f'Uso elevado de recursos detectado: CPU {cpu:.2f}%, Memória {memory:.2f} MB')
            
            time.sleep(1)
        
        proc.terminate()
        log_message('INFO', f'Análise dinâmica concluída para {file_path}')
    except Exception as e:
        log_message('ERRO', f'Erro na análise dinâmica de {file_path}: {e}')

# Função para monitoramento de rede
def network_analysis(duration):
    try:
        def packet_callback(packet):
            if IP in packet:
                ip_dst = packet[IP].dst
                if ip_dst in Settings['SuspiciousIPs']:
                    ScriptState['AnalysisResults']['Dynamic']['network'].append((ip_dst, 'Conexão a IP suspeito'))
                    ScriptState['TotalIssues'] += 1
                    log_message('CRÍTICO', f'Conexão a IP suspeito: {ip_dst}')
        
        sniff(iface=Settings['NetworkInterface'], prn=packet_callback, timeout=duration, store=False)
        log_message('INFO', 'Monitoramento de rede concluído.')
    except Exception as e:
        log_message('ERRO', f'Erro no monitoramento de rede: {e}')

# Função para integração com VirusTotal
def virustotal_analysis(file_path):
    if not Settings['VirusTotalApiKey']:
        log_message('ERRO', 'Chave da API do VirusTotal não configurada.')
        return
    try:
        sha256 = hashlib.sha256(open(file_path, 'rb').read()).hexdigest()
        url = f'https://www.virustotal.com/api/v3/files/{sha256}'
        headers = {'x-apikey': Settings['VirusTotalApiKey']}
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            ScriptState['AnalysisResults']['VirusTotal'] = stats
            if stats['malicious'] > 0:
                ScriptState['TotalIssues'] += 1
                log_message('CRÍTICO', f'Arquivo malicioso detectado pelo VirusTotal: {stats}')
            else:
                log_message('INFO', f'Nenhum malware detectado pelo VirusTotal: {stats}')
        else:
            log_message('ERRO', f'Erro na API do VirusTotal: {response.text}')
    except Exception as e:
        log_message('ERRO', f'Erro ao consultar VirusTotal para {file_path}: {e}')

# Função para exportar relatório em JSON
def export_json_report():
    os.makedirs(Settings['ReportDir'], exist_ok=True)
    report_path = os.path.join(Settings['ReportDir'], f'report_{int(time.time())}.json')
    report = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'results': ScriptState['AnalysisResults'],
        'total_issues': ScriptState['TotalIssues'],
    }
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    log_message('INFO', f'Relatório JSON salvo em {report_path}')

# Função para exportar relatório em CSV
def export_csv_report():
    os.makedirs(Settings['ReportDir'], exist_ok=True)
    report_path = os.path.join(Settings['ReportDir'], f'report_{int(time.time())}.csv')
    with open(report_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Timestamp', time.strftime('%Y-%m-%d %H:%M:%S')])
        writer.writerow(['Total de Problemas Detectados', ScriptState['TotalIssues']])
        writer.writerow([])
        writer.writerow(['Tipo', 'Detalhes'])
        for key, value in ScriptState['AnalysisResults']['Static'].items():
            writer.writerow(['Estática', f'{key}: {value}'])
        for entry in ScriptState['AnalysisResults']['Dynamic']['calls']:
            writer.writerow(['Dinâmica', f'{entry[0]}: {entry[1]}'])
        for entry in ScriptState['AnalysisResults']['Dynamic']['network']:
            writer.writerow(['Rede', f'{entry[0]}: {entry[1]}'])
        if ScriptState['AnalysisResults']['VirusTotal']:
            writer.writerow(['VirusTotal', str(ScriptState['AnalysisResults']['VirusTotal'])])
    log_message('INFO', f'Relatório CSV salvo em {report_path}')

# Função para exportar relatório em PDF
def export_pdf_report():
    os.makedirs(Settings['ReportDir'], exist_ok=True)
    report_path = os.path.join(Settings['ReportDir'], f'report_{int(time.time())}.pdf')
    doc = SimpleDocTemplate(report_path, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph('Relatório MalduarkAnaly', styles['Title']))
    story.append(Spacer(1, 12))
    
    story.append(Paragraph(f'Total de Problemas Detectados: {ScriptState["TotalIssues"]}', styles['Heading2']))
    story.append(Spacer(1, 12))
    
    table_data = [['Tipo', 'Detalhes']]
    for key, value in ScriptState['AnalysisResults']['Static'].items():
        table_data.append(['Estática', f'{key}: {value}'])
    for entry in ScriptState['AnalysisResults']['Dynamic']['calls']:
        table_data.append(['Dinâmica', f'{entry[0]}: {entry[1]}'])
    for entry in ScriptState['AnalysisResults']['Dynamic']['network']:
        table_data.append(['Rede', f'{entry[0]}: {entry[1]}'])
    if ScriptState['AnalysisResults']['VirusTotal']:
        table_data.append(['VirusTotal', str(ScriptState['AnalysisResults']['VirusTotal'])])
    
    table = Table(table_data)
    story.append(table)
    doc.build(story)
    log_message('INFO', f'Relatório PDF salvo em {report_path}')

# Função para exportar relatório em HTML
def export_html_report():
    os.makedirs(Settings['ReportDir'], exist_ok=True)
    report_path = os.path.join(Settings['ReportDir'], f'report_{int(time.time())}.html')
    template_path = os.path.join(Settings['ReportDir'], 'report_template.html')
    
    if not os.path.exists(template_path):
        with open(template_path, 'w') as f:
            f.write('''
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Relatório MalduarkAnaly</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
        th { background-color: #f0f0f0; }
        #issueChart { max-width: 600px; margin: 20px 0; }
        .section { margin-bottom: 20px; }
    </style>
</head>
<body>
    <h1>Relatório MalduarkAnaly</h1>
    <div class="section">
        <h2>Resumo</h2>
        <p><strong>Timestamp:</strong> {{timestamp}}</p>
        <p><strong>Total de Problemas:</strong> {{total_issues}}</p>
    </div>
    <div class="section">
        <h2>Distribuição de Problemas</h2>
        <canvas id="issueChart"></canvas>
    </div>
    <div class="section">
        <h2>Resultados</h2>
        <table id="resultsTable">
            <tr><th>Tipo</th><th>Detalhes</th></tr>
            {{results_table}}
        </table>
    </div>
    <script>
        const ctx = document.getElementById('issueChart').getContext('2d');
        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: {{issue_labels}},
                datasets: [{
                    label: 'Problemas',
                    data: {{issue_data}},
                    backgroundColor: '#007bff',
                    borderColor: '#0056b3',
                    borderWidth: 1
                }]
            },
            options: {
                scales: { y: { beginAtZero: true } }
            }
        });
    </script>
</body>
</html>
            ''')

    issue_types = {'Estática': 0, 'Dinâmica': 0, 'Rede': 0, 'VirusTotal': 0}
    results_table = ''
    for key, value in ScriptState['AnalysisResults']['Static'].items():
        results_table += f'<tr><td>Estática</td><td>{key}: {value}</td></tr>'
        issue_types['Estática'] += 1
    for entry in ScriptState['AnalysisResults']['Dynamic']['calls']:
        results_table += f'<tr><td>Dinâmica</td><td>{entry[0]}: {entry[1]}</td></tr>'
        issue_types['Dinâmica'] += 1
    for entry in ScriptState['AnalysisResults']['Dynamic']['network']:
        results_table += f'<tr><td>Rede</td><td>{entry[0]}: {entry[1]}</td></tr>'
        issue_types['Rede'] += 1
    if ScriptState['AnalysisResults']['VirusTotal']:
        results_table += f'<tr><td>VirusTotal</td><td>{ScriptState["AnalysisResults"]["VirusTotal"]}</td></tr>'
        issue_types['VirusTotal'] += 1
    
    with open(template_path, 'r') as f:
        template = f.read()
    
    html_content = template.replace('{{timestamp}}', time.strftime('%Y-%m-%d %H:%M:%S'))
    html_content = html_content.replace('{{total_issues}}', str(ScriptState['TotalIssues']))
    html_content = html_content.replace('{{results_table}}', results_table)
    html_content = html_content.replace('{{issue_labels}}', json.dumps(list(issue_types.keys())))
    html_content = html_content.replace('{{issue_data}}', json.dumps(list(issue_types.values())))
    
    with open(report_path, 'w') as f:
        f.write(html_content)
    log_message('INFO', f'Relatório HTML salvo em {report_path}')
    return report_path

# GUI com Tkinter
class MalduarkAnalyGUI:
    def __init__(self, root):
        self.root = root
        self.root.title('MalduarkAnaly - Hygark (2025)')
        self.root.geometry('1200x800')
        
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(pady=10, padx=10, fill='both', expand=True)

        # Aba de Configurações
        self.config_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.config_frame, text='Configurações')

        tk.Label(self.config_frame, text='MalduarkAnaly - Análise de Malware').pack(pady=10)
        
        tk.Label(self.config_frame, text='Arquivo para Análise:').pack()
        self.file_entry = tk.Entry(self.config_frame, width=60)
        self.file_entry.pack(pady=5)
        tk.Button(self.config_frame, text='Selecionar Arquivo', command=self.select_file).pack(pady=5)

        tk.Label(self.config_frame, text='Duração do Monitoramento (segundos):').pack()
        self.duration_entry = tk.Entry(self.config_frame, width=20)
        self.duration_entry.insert(0, str(Settings['MonitorDuration']))
        self.duration_entry.pack(pady=5)

        tk.Label(self.config_frame, text='Chave da API do VirusTotal:').pack()
        self.vt_key_entry = tk.Entry(self.config_frame, width=60)
        self.vt_key_entry.insert(0, Settings['VirusTotalApiKey'])
        self.vt_key_entry.pack(pady=5)

        tk.Label(self.config_frame, text='Interface de Rede:').pack()
        self.interface_entry = tk.Entry(self.config_frame, width=20)
        self.interface_entry.insert(0, Settings['NetworkInterface'])
        self.interface_entry.pack(pady=5)

        tk.Label(self.config_frame, text='Servidor Syslog:').pack()
        self.syslog_server_entry = tk.Entry(self.config_frame, width=60)
        self.syslog_server_entry.insert(0, Settings['SyslogServer'])
        self.syslog_server_entry.pack(pady=5)

        tk.Label(self.config_frame, text='Porta Syslog:').pack()
        self.syslog_port_entry = tk.Entry(self.config_frame, width=20)
        self.syslog_port_entry.insert(0, str(Settings['SyslogPort']))
        self.syslog_port_entry.pack(pady=5)

        tk.Label(self.config_frame, text='Exportações:').pack(pady=5)
        self.check_vars = {
            'JSON': tk.BooleanVar(value=Settings['ExportJSON']),
            'CSV': tk.BooleanVar(value=Settings['ExportCSV']),
            'PDF': tk.BooleanVar(value=Settings['ExportPDF']),
            'HTML': tk.BooleanVar(value=Settings['ExportHTML']),
        }
        export_frame = tk.Frame(self.config_frame)
        export_frame.pack()
        for i, (name, var) in enumerate(self.check_vars.items()):
            tk.Checkbutton(export_frame, text=name, variable=var).grid(row=0, column=i, padx=5, pady=2, sticky='w')

        # Aba de Dashboard
        self.dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.dashboard_frame, text='Dashboard')

        self.progress_var = tk.StringVar(value='Progresso: Aguardando análise...')
        tk.Label(self.dashboard_frame, textvariable=self.progress_var).pack(pady=10)

        self.progress_bar = ttk.Progressbar(self.dashboard_frame, length=400, mode='determinate')
        self.progress_bar.pack(pady=5)

        self.cpu_canvas = tk.Canvas(self.dashboard_frame)
        self.cpu_canvas.pack(pady=10, fill='both', expand=True)
        self.cpu_figure, self.cpu_ax = plt.subplots(figsize=(6, 4))
        self.cpu_canvas_widget = FigureCanvasTkAgg(self.cpu_figure, master=self.cpu_canvas)
        self.cpu_canvas_widget.get_tk_widget().pack()

        # Aba de Resultados
        self.result_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.result_frame, text='Resultados')

        self.result_text = tk.Text(self.result_frame, height=15, width=80)
        self.result_text.pack(pady=10, padx=10)

        # Aba de Relatórios
        self.reports_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.reports_frame, text='Relatórios')

        self.html_frame = HtmlFrame(self.reports_frame, height=400)
        self.html_frame.pack(pady=10, padx=10, fill='both', expand=True)

        # Botões
        button_frame = tk.Frame(self.result_frame)
        button_frame.pack(pady=5)
        tk.Button(button_frame, text='Iniciar Análise', command=self.start_analysis).pack(side='left', padx=5)
        tk.Button(button_frame, text='Parar Análise', command=self.stop_analysis).pack(side='left', padx=5)
        tk.Button(button_frame, text='Salvar Configurações', command=self.save_settings).pack(side='left', padx=5)
        tk.Button(button_frame, text='Visualizar Gráficos', command=self.show_graphs).pack(side='left', padx=5)
        tk.Button(button_frame, text='Exportar Relatórios', command=self.export_reports).pack(side='left', padx=5)

    def select_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, file_path)

    def start_analysis(self):
        if ScriptState['IsRunning']:
            messagebox.showerror('Erro', 'Análise já em andamento!')
            return
        ScriptState['IsRunning'] = True
        ScriptState['AnalysisResults'] = {'Static': {}, 'Dynamic': {'cpu': [], 'memory': [], 'network': [], 'calls': []}, 'VirusTotal': {}}
        ScriptState['TotalIssues'] = 0
        self.result_text.delete(1.0, tk.END)
        
        file_path = self.file_entry.get()
        if not file_path or not os.path.exists(file_path):
            messagebox.showerror('Erro', 'Selecione um arquivo válido!')
            ScriptState['IsRunning'] = False
            return
        
        try:
            Settings['MonitorDuration'] = int(self.duration_entry.get())
            Settings['NetworkInterface'] = self.interface_entry.get()
        except ValueError as e:
            messagebox.showerror('Erro', f'Entrada inválida: {e}')
            ScriptState['IsRunning'] = False
            return
        
        def analysis_thread():
            log_message('INFO', f'Iniciando análise de {file_path}')
            self.result_text.insert(tk.END, f'Iniciando análise de {file_path}...\n')
            
            static_analysis(file_path)
            self.result_text.insert(tk.END, 'Análise estática concluída.\n')
            
            threading.Thread(target=network_analysis, args=(Settings['MonitorDuration'],), daemon=True).start()
            dynamic_analysis(file_path, Settings['MonitorDuration'])
            self.result_text.insert(tk.END, 'Análise dinâmica concluída.\n')
            
            if Settings['VirusTotalApiKey']:
                virustotal_analysis(file_path)
                self.result_text.insert(tk.END, 'Análise VirusTotal concluída.\n')
            
            ScriptState['IsRunning'] = False
            self.result_text.insert(tk.END, 'Análise finalizada.\n')
            self.update_dashboard()
        
        threading.Thread(target=analysis_thread, daemon=True).start()

    def stop_analysis(self):
        ScriptState['IsRunning'] = False
        self.result_text.insert(tk.END, 'Análise parada.\n')
        log_message('INFO', 'Análise parada.')

    def save_settings(self):
        try:
            Settings['VirusTotalApiKey'] = self.vt_key_entry.get()
            Settings['SyslogServer'] = self.syslog_server_entry.get()
            Settings['SyslogPort'] = int(self.syslog_port_entry.get())
            Settings['NetworkInterface'] = self.interface_entry.get()
            Settings['MonitorDuration'] = int(self.duration_entry.get())
            for name, var in self.check_vars.items():
                Settings[f'Export{name}'] = var.get()
            messagebox.showinfo('Sucesso', 'Configurações salvas.')
            log_message('INFO', 'Configurações salvas.')
        except Exception as e:
            messagebox.showerror('Erro', f'Erro ao salvar configurações: {e}')
            log_message('ERRO', f'Erro ao salvar configurações: {e}')

    def update_dashboard(self):
        self.progress_var.set(f'Progresso: {ScriptState["TotalIssues"]} problemas detectados')
        self.progress_bar['value'] = 100 if not ScriptState['IsRunning'] else 50
        
        self.cpu_ax.clear()
        if ScriptState['AnalysisResults']['Dynamic']['cpu']:
            self.cpu_ax.plot(ScriptState['AnalysisResults']['Dynamic']['cpu'], label='CPU (%)')
            self.cpu_ax.plot(ScriptState['AnalysisResults']['Dynamic']['memory'], label='Memória (MB)')
            self.cpu_ax.set_title('Uso de Recursos')
            self.cpu_ax.legend()
        else:
            self.cpu_ax.text(0.5, 0.5, 'Nenhum dado dinâmico disponível.', horizontalalignment='center', verticalalignment='center')
        self.cpu_canvas_widget.draw()

        self.result_text.delete(1.0, tk.END)
        for key, value in ScriptState['AnalysisResults']['Static'].items():
            self.result_text.insert(tk.END, f'Estática - {key}: {value}\n')
        for entry in ScriptState['AnalysisResults']['Dynamic']['calls']:
            self.result_text.insert(tk.END, f'Dinâmica - {entry[0]}: {entry[1]}\n')
        for entry in ScriptState['AnalysisResults']['Dynamic']['network']:
            self.result_text.insert(tk.END, f'Rede - {entry[0]}: {entry[1]}\n')
        if ScriptState['AnalysisResults']['VirusTotal']:
            self.result_text.insert(tk.END, f'VirusTotal: {ScriptState["AnalysisResults"]["VirusTotal"]}\n')

    def show_graphs(self):
        if not ScriptState['AnalysisResults']['Dynamic']['cpu']:
            messagebox.showinfo('Info', 'Nenhum dado para exibir.')
            return
        self.notebook.select(self.dashboard_frame)
        self.update_dashboard()

    def export_reports(self):
        if Settings['ExportJSON']:
            export_json_report()
        if Settings['ExportCSV']:
            export_csv_report()
        if Settings['ExportPDF']:
            export_pdf_report()
        if Settings['ExportHTML']:
            report_path = export_html_report()
            self.html_frame.load_file(report_path)
        messagebox.showinfo('Sucesso', 'Relatórios exportados com sucesso.')
        log_message('INFO', 'Relatórios exportados com sucesso.')

# Função principal
def main():
    root = tk.Tk()
    app = MalduarkAnalyGUI(root)
    root.mainloop()

if __name__ == '__main__':
    main()