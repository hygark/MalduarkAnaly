# MalduarkAnaly.py - Ferramenta de Análise de Malware em Ambiente Isolado (2025)
# Criado por Hygark (2025)
# Descrição: Ferramenta para análise estática e dinâmica de arquivos suspeitos, com suporte a múltiplos formatos (.exe, .dll, .py, .ps1, .doc, .pdf, .jar, .apk), monitoramento de processos, rede, integração com VirusTotal, Cuckoo Sandbox, Hybrid Analysis, Joe Sandbox, detecção de ofuscação, análise de comportamento com ML, relatórios em JSON/CSV/PDF/HTML e GUI Tkinter.

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
import ast  # Para análise de Python
import re  # Para análise de PowerShell
import platform  # Para compatibilidade multiplataforma
import base64  # Para detecção de ofuscação
from docx import Document  # Para análise de .doc/.docx
import pdfid  # Para análise de PDFs
import zipfile  # Para análise de .jar/.apk
from sklearn.ensemble import IsolationForest  # Para análise de comportamento com ML
import numpy as np

# Configurações personalizáveis
Settings = {
    'FilePath': '',  # Caminho do arquivo a ser analisado
    'MonitorDuration': 30,  # Duração do monitoramento (segundos)
    'VirusTotalApiKey': '',  # Chave da API do VirusTotal
    'CuckooApiUrl': 'http://localhost:8090',  # URL da API do Cuckoo Sandbox
    'CuckooApiKey': '',  # Chave da API do Cuckoo Sandbox
    'HybridAnalysisApiKey': '',  # Chave da API do Hybrid Analysis
    'JoeSandboxApiKey': '',  # Chave da API do Joe Sandbox
    'JoeSandboxApiUrl': 'https://www.joesandbox.com/api',  # URL da API do Joe Sandbox
    'LogFile': 'logs/malduark_analy.log',  # Arquivo de log
    'LogWebhook': '',  # URL de webhook
    'SyslogServer': '',  # Servidor Syslog
    'SyslogPort': 514,  # Porta Syslog
    'ReportDir': 'reports/',  # Diretório para relatórios
    'ExportJSON': True,  # Exportar em JSON
    'ExportCSV': True,  # Exportar em CSV
    'ExportPDF': True,  # Exportar em PDF
    'ExportHTML': True,  # Exportar em HTML
    'SuspiciousIPs': ['127.0.0.1', '169.254.169.254'],  # IPs suspeitos
    'SuspiciousCalls': ['CreateFile', 'Connect', 'RegCreateKey'],  # Chamadas de sistema suspeitas
    'NetworkInterface': 'eth0' if platform.system() != 'Windows' else 'Ethernet',  # Interface de rede
    'SuspiciousPatterns': {  # Padrões maliciosos para scripts
        'python': [r'eval\(', r'exec\(', r'os\.system\(', r'subprocess\.call\(', r'requests\.get\('],
        'powershell': [r'Invoke-Expression', r'Invoke-WebRequest', r'Start-Process', r'New-Object System.Net.WebClient'],
        'vba': [r'CreateObject', r'WScript.Shell', r'Run', r'GetObject'],
        'pdf': [r'/JS', r'/JavaScript', r'/OpenAction', r'/AA'],
    },
}

# Estado do script
ScriptState = {
    'IsRunning': False,
    'AnalysisResults': {
        'Static': {},
        'Dynamic': {'cpu': [], 'memory': [], 'network': [], 'calls': []},
        'VirusTotal': {},
        'Cuckoo': {},
        'HybridAnalysis': {},
        'JoeSandbox': {},
        'ScriptAnalysis': {},
        'Obfuscation': {},
        'MLAnalysis': {},
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

# Função para detectar ofuscação
def detect_obfuscation(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        obfuscation_indicators = []
        if re.search(r'base64\.b64decode\(', content) or re.search(r'decode\(', content):
            obfuscation_indicators.append('Base64 decoding detected')
        if len(content) > 1000 and len(set(content)) / len(content) < 0.1:  # Baixa entropia
            obfuscation_indicators.append('Possible packed/obfuscated code')
        if re.search(r'[\x00-\x1F\x7F-\xFF]', content):  # Caracteres não-ASCII
            obfuscation_indicators.append('Non-ASCII characters detected')
        
        if obfuscation_indicators:
            ScriptState['TotalIssues'] += len(obfuscation_indicators)
            ScriptState['AnalysisResults']['Obfuscation'] = {'File': file_path, 'Indicators': obfuscation_indicators}
            log_message('AVISO', f'Ofuscação detectada em {file_path}: {obfuscation_indicators}')
        else:
            ScriptState['AnalysisResults']['Obfuscation'] = {'File': file_path, 'Indicators': []}
            log_message('INFO', f'Nenhuma ofuscação detectada em {file_path}')
    except Exception as e:
        log_message('ERRO', f'Erro na detecção de ofuscação em {file_path}: {e}')

# Função para análise estática
def static_analysis(file_path):
    try:
        ext = os.path.splitext(file_path)[1].lower()
        static_data = {
            'File': os.path.basename(file_path),
            'MD5': hashlib.md5(open(file_path, 'rb').read()).hexdigest(),
            'SHA256': hashlib.sha256(open(file_path, 'rb').read()).hexdigest(),
        }
        
        if ext in ['.exe', '.dll']:
            pe = pefile.PE(file_path)
            static_data['EntryPoint'] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            static_data['ImageBase'] = hex(pe.OPTIONAL_HEADER.ImageBase)
            static_data['Sections'] = [s.Name.decode().strip('\x00') for s in pe.sections]
            static_data['Imports'] = []
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            static_data['Imports'].append(imp.name.decode())
            
            suspicious_imports = [imp for imp in static_data['Imports'] if any(call in imp for call in Settings['SuspiciousCalls'])]
            if suspicious_imports:
                ScriptState['TotalIssues'] += len(suspicious_imports)
                static_data['SuspiciousImports'] = suspicious_imports
                for imp in suspicious_imports:
                    log_message('AVISO', f'Importação suspeita detectada: {imp}')
        
        elif ext in ['.doc', '.docx']:
            doc = Document(file_path)
            for paragraph in doc.paragraphs:
                if any(pattern in paragraph.text for pattern in Settings['SuspiciousPatterns']['vba']):
                    ScriptState['TotalIssues'] += 1
                    static_data['SuspiciousVBA'] = paragraph.text
                    log_message('AVISO', f'Código VBA suspeito detectado em {file_path}: {paragraph.text}')
        
        elif ext == '.pdf':
            pdf_report = pdfid.PDFiD(file_path)
            xml_doc = pdfid.PDFiD2XML(pdf_report)
            suspicious_elements = [obj for obj in xml_doc.getElementsByTagName('obj') if any(pattern in obj.getAttribute('name') for pattern in Settings['SuspiciousPatterns']['pdf'])]
            if suspicious_elements:
                ScriptState['TotalIssues'] += len(suspicious_elements)
                static_data['SuspiciousPDFElements'] = [obj.getAttribute('name') for obj in suspicious_elements]
                log_message('AVISO', f'Elementos suspeitos em PDF {file_path}: {static_data["SuspiciousPDFElements"]}')
        
        elif ext in ['.jar', '.apk']:
            with zipfile.ZipFile(file_path, 'r') as z:
                static_data['Files'] = z.namelist()
                if ext == '.apk':
                    if 'AndroidManifest.xml' in static_data['Files']:
                        with z.open('AndroidManifest.xml') as f:
                            manifest = f.read().decode('utf-8', errors='ignore')
                            suspicious_permissions = re.findall(r'android\.permission\.(INTERNET|WRITE_EXTERNAL_STORAGE|READ_PHONE_STATE)', manifest)
                            if suspicious_permissions:
                                ScriptState['TotalIssues'] += len(suspicious_permissions)
                                static_data['SuspiciousPermissions'] = suspicious_permissions
                                log_message('AVISO', f'Permissões suspeitas em APK {file_path}: {suspicious_permissions}')
        
        ScriptState['AnalysisResults']['Static'] = static_data
        log_message('INFO', f'Análise estática concluída para {file_path}')
    except Exception as e:
        log_message('ERRO', f'Erro na análise estática de {file_path}: {e}')

# Função para análise de scripts (PowerShell, Python)
def script_analysis(file_path):
    ext = os.path.splitext(file_path)[1].lower()
    if ext not in ['.py', '.ps1']:
        log_message('AVISO', f'Formato de script não suportado: {ext}')
        return
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            code = f.read()
        
        suspicious_patterns = []
        if ext == '.py':
            try:
                tree = ast.parse(code)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Call):
                        if isinstance(node.func, ast.Name) and node.func.id in ['eval', 'exec']:
                            suspicious_patterns.append(node.func.id)
                        elif isinstance(node.func, ast.Attribute) and node.func.value.id in ['os', 'subprocess', 'requests']:
                            suspicious_patterns.append(f"{node.func.value.id}.{node.func.attr}")
            except SyntaxError as e:
                log_message('ERRO', f'Erro de sintaxe no script Python {file_path}: {e}')
        
        elif ext == '.ps1':
            patterns = Settings['SuspiciousPatterns']['powershell']
            suspicious_patterns = re.findall('|'.join(patterns), code, re.IGNORECASE)
        
        if suspicious_patterns:
            ScriptState['TotalIssues'] += len(suspicious_patterns)
            ScriptState['AnalysisResults']['ScriptAnalysis'] = {'File': file_path, 'Patterns': suspicious_patterns}
            log_message('AVISO', f'Padrões suspeitos em script {ext}: {suspicious_patterns}')
        else:
            ScriptState['AnalysisResults']['ScriptAnalysis'] = {'File': file_path, 'Patterns': []}
            log_message('INFO', f'Nenhum padrão suspeito encontrado em script {ext}')
    except Exception as e:
        log_message('ERRO', f'Erro na análise de script {file_path}: {e}')

# Função para análise dinâmica
def dynamic_analysis(file_path, duration):
    try:
        ext = os.path.splitext(file_path)[1].lower()
        if ext == '.py':
            cmd = ['python3' if platform.system() != 'Windows' else 'python', file_path]
        elif ext == '.ps1':
            cmd = ['pwsh' if platform.system() != 'Windows' else 'powershell', '-File', file_path]
        elif ext in ['.exe', '.dll']:
            cmd = [file_path]
        else:
            log_message('AVISO', f'Formato não suportado para análise dinâmica: {ext}')
            return
        
        proc = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        ps_proc = psutil.Process(proc.pid)
        start_time = time.time()
        
        while time.time() - start_time < duration and ps_proc.is_running():
            cpu = ps_proc.cpu_percent(interval=0.1)
            memory = ps_proc.memory_info().rss / 1024**2  # MB
            ScriptState['AnalysisResults']['Dynamic']['cpu'].append(cpu)
            ScriptState['AnalysisResults']['Dynamic']['memory'].append(memory)
            
            if cpu > 80 or memory > 500:  # Limites arbitrários
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

# Função para análise com ML
def ml_analysis():
    try:
        cpu_data = ScriptState['AnalysisResults']['Dynamic']['cpu']
        memory_data = ScriptState['AnalysisResults']['Dynamic']['memory']
        if not cpu_data or not memory_data:
            log_message('INFO', 'Nenhum dado dinâmico para análise de ML.')
            return
        
        data = np.array(list(zip(cpu_data, memory_data)))
        model = IsolationForest(contamination=0.1, random_state=42)
        predictions = model.fit_predict(data)
        
        anomalies = [i for i, pred in enumerate(predictions) if pred == -1]
        if anomalies:
            ScriptState['TotalIssues'] += len(anomalies)
            ScriptState['AnalysisResults']['MLAnalysis'] = {'Anomalies': anomalies}
            log_message('AVISO', f'Anomalias detectadas por ML: {len(anomalies)} pontos anômalos')
        else:
            ScriptState['AnalysisResults']['MLAnalysis'] = {'Anomalies': []}
            log_message('INFO', 'Nenhuma anomalia detectada por ML.')
    except Exception as e:
        log_message('ERRO', f'Erro na análise de ML: {e}')

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

# Função para integração com Cuckoo Sandbox
def cuckoo_analysis(file_path):
    if not Settings['CuckooApiKey'] or not Settings['CuckooApiUrl']:
        log_message('ERRO', 'Configuração da API do Cuckoo Sandbox incompleta.')
        return
    try:
        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f)}
            headers = {'Authorization': f'Bearer {Settings["CuckooApiKey"]}'}
            response = requests.post(f"{Settings['CuckooApiUrl']}/tasks/create/file", files=files, headers=headers, timeout=10)
            if response.status_code == 200:
                task_id = response.json()['task_id']
                log_message('INFO', f'Arquivo enviado para Cuckoo Sandbox, ID da tarefa: {task_id}')
                for _ in range(60):
                    report_response = requests.get(f"{Settings['CuckooApiUrl']}/tasks/report/{task_id}/json", headers=headers, timeout=5)
                    if report_response.status_code == 200:
                        report = report_response.json()
                        cuckoo_summary = {
                            'score': report.get('info', {}).get('score', 0),
                            'signatures': [sig['name'] for sig in report.get('signatures', [])],
                            'network': report.get('network', {}).get('hosts', []),
                        }
                        ScriptState['AnalysisResults']['Cuckoo'] = cuckoo_summary
                        if cuckoo_summary['score'] > 5:
                            ScriptState['TotalIssues'] += 1
                            log_message('CRÍTICO', f'Cuckoo detectou comportamento malicioso (pontuação: {cuckoo_summary["score"]})')
                        else:
                            log_message('INFO', f'Cuckoo não detectou comportamento malicioso (pontuação: {cuckoo_summary["score"]})')
                        break
                    time.sleep(10)
            else:
                log_message('ERRO', f'Erro ao enviar arquivo para Cuckoo: {response.text}')
    except Exception as e:
        log_message('ERRO', f'Erro ao integrar com Cuckoo Sandbox para {file_path}: {e}')

# Função para integração com Hybrid Analysis
def hybrid_analysis(file_path):
    if not Settings['HybridAnalysisApiKey']:
        log_message('ERRO', 'Chave da API do Hybrid Analysis não configurada.')
        return
    try:
        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f)}
            headers = {'api-key': Settings['HybridAnalysisApiKey'], 'user-agent': 'MalduarkAnaly'}
            response = requests.post('https://www.hybrid-analysis.com/api/v2/submit/file', files=files, headers=headers, timeout=10)
            if response.status_code == 200:
                job_id = response.json()['job_id']
                log_message('INFO', f'Arquivo enviado para Hybrid Analysis, ID do job: {job_id}')
                for _ in range(60):
                    report_response = requests.get(f'https://www.hybrid-analysis.com/api/v2/report/{job_id}/summary', headers=headers, timeout=5)
                    if report_response.status_code == 200:
                        report = report_response.json()
                        hybrid_summary = {
                            'verdict': report.get('verdict', 'unknown'),
                            'threat_score': report.get('threat_score', 0),
                            'av_detect': report.get('av_detect', 0),
                        }
                        ScriptState['AnalysisResults']['HybridAnalysis'] = hybrid_summary
                        if hybrid_summary['threat_score'] > 50:
                            ScriptState['TotalIssues'] += 1
                            log_message('CRÍTICO', f'Hybrid Analysis detectou ameaça (pontuação: {hybrid_summary["threat_score"]})')
                        else:
                            log_message('INFO', f'Hybrid Analysis não detectou ameaça (pontuação: {hybrid_summary["threat_score"]})')
                        break
                    time.sleep(10)
            else:
                log_message('ERRO', f'Erro ao enviar arquivo para Hybrid Analysis: {response.text}')
    except Exception as e:
        log_message('ERRO', f'Erro ao integrar com Hybrid Analysis para {file_path}: {e}')

# Função para integração com Joe Sandbox
def joe_sandbox_analysis(file_path):
    if not Settings['JoeSandboxApiKey']:
        log_message('ERRO', 'Chave da API do Joe Sandbox não configurada.')
        return
    try:
        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f)}
            data = {'parameters': json.dumps({'analysis-time': Settings['MonitorDuration']})}
            headers = {'Authorization': f'Bearer {Settings["JoeSandboxApiKey"]}'}
            response = requests.post(f"{Settings['JoeSandboxApiUrl']}/submit", files=files, data=data, headers=headers, timeout=10)
            if response.status_code == 200:
                analysis_id = response.json()['data']['analysis_id']
                log_message('INFO', f'Arquivo enviado para Joe Sandbox, ID da análise: {analysis_id}')
                for _ in range(60):
                    report_response = requests.get(f"{Settings['JoeSandboxApiUrl']}/analysis/{analysis_id}/report", headers=headers, timeout=5)
                    if report_response.status_code == 200:
                        report = report_response.json()
                        joe_summary = {
                            'score': report.get('score', 0),
                            'signatures': report.get('signatures', []),
                        }
                        ScriptState['AnalysisResults']['JoeSandbox'] = joe_summary
                        if joe_summary['score'] > 50:
                            ScriptState['TotalIssues'] += 1
                            log_message('CRÍTICO', f'Joe Sandbox detectou ameaça (pontuação: {joe_summary["score"]})')
                        else:
                            log_message('INFO', f'Joe Sandbox não detectou ameaça (pontuação: {joe_summary["score"]})')
                        break
                    time.sleep(10)
            else:
                log_message('ERRO', f'Erro ao enviar arquivo para Joe Sandbox: {response.text}')
    except Exception as e:
        log_message('ERRO', f'Erro ao integrar com Joe Sandbox para {file_path}: {e}')

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
        if ScriptState['AnalysisResults']['Cuckoo']:
            writer.writerow(['Cuckoo Sandbox', str(ScriptState['AnalysisResults']['Cuckoo'])])
        if ScriptState['AnalysisResults']['HybridAnalysis']:
            writer.writerow(['Hybrid Analysis', str(ScriptState['AnalysisResults']['HybridAnalysis'])])
        if ScriptState['AnalysisResults']['JoeSandbox']:
            writer.writerow(['Joe Sandbox', str(ScriptState['AnalysisResults']['JoeSandbox'])])
        if ScriptState['AnalysisResults']['ScriptAnalysis']:
            writer.writerow(['Análise de Script', str(ScriptState['AnalysisResults']['ScriptAnalysis'])])
        if ScriptState['AnalysisResults']['Obfuscation']:
            writer.writerow(['Ofuscação', str(ScriptState['AnalysisResults']['Obfuscation'])])
        if ScriptState['AnalysisResults']['MLAnalysis']:
            writer.writerow(['Análise de ML', str(ScriptState['AnalysisResults']['MLAnalysis'])])
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
    if ScriptState['AnalysisResults']['Cuckoo']:
        table_data.append(['Cuckoo Sandbox', str(ScriptState['AnalysisResults']['Cuckoo'])])
    if ScriptState['AnalysisResults']['HybridAnalysis']:
        table_data.append(['Hybrid Analysis', str(ScriptState['AnalysisResults']['HybridAnalysis'])])
    if ScriptState['AnalysisResults']['JoeSandbox']:
        table_data.append(['Joe Sandbox', str(ScriptState['AnalysisResults']['JoeSandbox'])])
    if ScriptState['AnalysisResults']['ScriptAnalysis']:
        table_data.append(['Análise de Script', str(ScriptState['AnalysisResults']['ScriptAnalysis'])])
    if ScriptState['AnalysisResults']['Obfuscation']:
        table_data.append(['Ofuscação', str(ScriptState['AnalysisResults']['Obfuscation'])])
    if ScriptState['AnalysisResults']['MLAnalysis']:
        table_data.append(['Análise de ML', str(ScriptState['AnalysisResults']['MLAnalysis'])])
    
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

    issue_types = {'Estática': 0, 'Dinâmica': 0, 'Rede': 0, 'VirusTotal': 0, 'Cuckoo': 0, 'HybridAnalysis': 0, 'JoeSandbox': 0, 'Análise de Script': 0, 'Ofuscação': 0, 'Análise de ML': 0}
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
    if ScriptState['AnalysisResults']['Cuckoo']:
        results_table += f'<tr><td>Cuckoo Sandbox</td><td>{ScriptState["AnalysisResults"]["Cuckoo"]}</td></tr>'
        issue_types['Cuckoo'] += 1
    if ScriptState['AnalysisResults']['HybridAnalysis']:
        results_table += f'<tr><td>Hybrid Analysis</td><td>{ScriptState["AnalysisResults"]["HybridAnalysis"]}</td></tr>'
        issue_types['HybridAnalysis'] += 1
    if ScriptState['AnalysisResults']['JoeSandbox']:
        results_table += f'<tr><td>Joe Sandbox</td><td>{ScriptState["AnalysisResults"]["JoeSandbox"]}</td></tr>'
        issue_types['JoeSandbox'] += 1
    if ScriptState['AnalysisResults']['ScriptAnalysis']:
        results_table += f'<tr><td>Análise de Script</td><td>{ScriptState["AnalysisResults"]["ScriptAnalysis"]}</td></tr>'
        issue_types['Análise de Script'] += 1
    if ScriptState['AnalysisResults']['Obfuscation']:
        results_table += f'<tr><td>Ofuscação</td><td>{ScriptState["AnalysisResults"]["Obfuscation"]}</td></tr>'
        issue_types['Ofuscação'] += 1
    if ScriptState['AnalysisResults']['MLAnalysis']:
        results_table += f'<tr><td>Análise de ML</td><td>{ScriptState["AnalysisResults"]["MLAnalysis"]}</td></tr>'
        issue_types['Análise de ML'] += 1
    
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

        tk.Label(self.config_frame, text='URL da API do Cuckoo Sandbox:').pack()
        self.cuckoo_url_entry = tk.Entry(self.config_frame, width=60)
        self.cuckoo_url_entry.insert(0, Settings['CuckooApiUrl'])
        self.cuckoo_url_entry.pack(pady=5)

        tk.Label(self.config_frame, text='Chave da API do Cuckoo Sandbox:').pack()
        self.cuckoo_key_entry = tk.Entry(self.config_frame, width=60)
        self.cuckoo_key_entry.insert(0, Settings['CuckooApiKey'])
        self.cuckoo_key_entry.pack(pady=5)

        tk.Label(self.config_frame, text='Chave da API do Hybrid Analysis:').pack()
        self.hybrid_key_entry = tk.Entry(self.config_frame, width=60)
        self.hybrid_key_entry.insert(0, Settings['HybridAnalysisApiKey'])
        self.hybrid_key_entry.pack(pady=5)

        tk.Label(self.config_frame, text='Chave da API do Joe Sandbox:').pack()
        self.joe_key_entry = tk.Entry(self.config_frame, width=60)
        self.joe_key_entry.insert(0, Settings['JoeSandboxApiKey'])
        self.joe_key_entry.pack(pady=5)

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
        file_path = filedialog.askopenfilename(filetypes=[("Arquivos Suportados", "*.exe;*.dll;*.py;*.ps1;*.doc;*.docx;*.pdf;*.jar;*.apk"), ("Todos os arquivos", "*.*")])
        if file_path:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, file_path)

    def start_analysis(self):
        if ScriptState['IsRunning']:
            messagebox.showerror('Erro', 'Análise já em andamento!')
            return
        ScriptState['IsRunning'] = True
        ScriptState['AnalysisResults'] = {
            'Static': {}, 'Dynamic': {'cpu': [], 'memory': [], 'network': [], 'calls': []},
            'VirusTotal': {}, 'Cuckoo': {}, 'HybridAnalysis': {}, 'JoeSandbox': {},
            'ScriptAnalysis': {}, 'Obfuscation': {}, 'MLAnalysis': {}
        }
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
            
            if os.path.splitext(file_path)[1].lower() in ['.py', '.ps1']:
                script_analysis(file_path)
                self.result_text.insert(tk.END, 'Análise de script concluída.\n')
                detect_obfuscation(file_path)
                self.result_text.insert(tk.END, 'Detecção de ofuscação concluída.\n')
            
            threading.Thread(target=network_analysis, args=(Settings['MonitorDuration'],), daemon=True).start()
            dynamic_analysis(file_path, Settings['MonitorDuration'])
            self.result_text.insert(tk.END, 'Análise dinâmica concluída.\n')
            
            ml_analysis()
            self.result_text.insert(tk.END, 'Análise de ML concluída.\n')
            
            if Settings['VirusTotalApiKey']:
                virustotal_analysis(file_path)
                self.result_text.insert(tk.END, 'Análise VirusTotal concluída.\n')
            
            if Settings['CuckooApiKey']:
                cuckoo_analysis(file_path)
                self.result_text.insert(tk.END, 'Análise Cuckoo Sandbox concluída.\n')
            
            if Settings['HybridAnalysisApiKey']:
                hybrid_analysis(file_path)
                self.result_text.insert(tk.END, 'Análise Hybrid Analysis concluída.\n')
            
            if Settings['JoeSandboxApiKey']:
                joe_sandbox_analysis(file_path)
                self.result_text.insert(tk.END, 'Análise Joe Sandbox concluída.\n')
            
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
            Settings['CuckooApiUrl'] = self.cuckoo_url_entry.get()
            Settings['CuckooApiKey'] = self.cuckoo_key_entry.get()
            Settings['HybridAnalysisApiKey'] = self.hybrid_key_entry.get()
            Settings['JoeSandboxApiKey'] = self.joe_key_entry.get()
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
        if ScriptState['AnalysisResults']['Cuckoo']:
            self.result_text.insert(tk.END, f'Cuckoo Sandbox: {ScriptState["AnalysisResults"]["Cuckoo"]}\n')
        if ScriptState['AnalysisResults']['HybridAnalysis']:
            self.result_text.insert(tk.END, f'Hybrid Analysis: {ScriptState["AnalysisResults"]["HybridAnalysis"]}\n')
        if ScriptState['AnalysisResults']['JoeSandbox']:
            self.result_text.insert(tk.END, f'Joe Sandbox: {ScriptState["AnalysisResults"]["JoeSandbox"]}\n')
        if ScriptState['AnalysisResults']['ScriptAnalysis']:
            self.result_text.insert(tk.END, f'Análise de Script: {ScriptState["AnalysisResults"]["ScriptAnalysis"]}\n')
        if ScriptState['AnalysisResults']['Obfuscation']:
            self.result_text.insert(tk.END, f'Ofuscação: {ScriptState["AnalysisResults"]["Obfuscation"]}\n')
        if ScriptState['AnalysisResults']['MLAnalysis']:
            self.result_text.insert(tk.END, f'Análise de ML: {ScriptState["AnalysisResults"]["MLAnalysis"]}\n')

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