import sys
import webbrowser
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton, QMessageBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QFrame, QTextEdit
)
from PyQt5.QtGui import QColor, QFont, QCursor
from PyQt5.QtCore import Qt
import requests

VT_API_KEY = "8b6ae39de56e184ec7cfd23b681b77ac2d9ac063ea991815138a494c9d3a34da"
HA_API_KEY = "m49duwkm4273eeb2p0dawpg35cc327e46i0xqqxhceb72db3kiqhbf62a58b6b3f"

ENGINE_LINKS = {
    'Kaspersky': 'https://opentip.kaspersky.com/{query}/',
    'Fortinet': 'https://fortiguard.com/search?q={query}',
    'ESET-NOD32': 'https://www.virusradar.com/en/search/{query}',
}

def get_engine_link(engine, query):
    if engine in ENGINE_LINKS:
        return ENGINE_LINKS[engine].format(query=query)
    return None

def mitre_link(tid):
    if tid and tid.startswith("T"):
        return f"https://attack.mitre.org/techniques/{tid}/"
    return None

def verdict_chip(verdict):
    verdict = verdict.lower()
    color = {
        'malicious': QColor(255, 85, 85),
        'harmless': QColor(68, 211, 98),
        'suspicious': QColor(255, 165, 0),
        'undetected': QColor(68, 211, 98),
        'unknown': QColor(170, 178, 189),
        'no result': QColor(170, 178, 189)
    }.get(verdict, QColor(232, 234, 237))
    icon = {
        'malicious': '✖',
        'harmless': '✔',
        'suspicious': '⚠',
        'undetected': '✔',
        'unknown': '?',
        'no result': '?'
    }.get(verdict, '?')
    return icon, color

class MitrePanel(QFrame):
    def __init__(self):
        super().__init__()
        self.setFrameShape(QFrame.StyledPanel)
        self.setStyleSheet('''
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #1a232a, stop:1 #10131a);
                border-radius: 20px;
                border: 2px solid #00BFFF;
                margin: 0px 0px 0px 16px;
            }
        ''')
        self.layout = QVBoxLayout()
        self.setLayout(self.layout)
        self.title = QLabel('MITRE ATT&CK Dashboard')
        self.title.setStyleSheet('font-size: 26px; font-weight: bold; color: #00BFFF; margin-bottom: 10px; letter-spacing:1px;')
        self.layout.addWidget(self.title, alignment=Qt.AlignCenter)
        self.content = QTextEdit()
        self.content.setReadOnly(True)
        self.content.setStyleSheet('background: transparent; color: #E8EAED; font-size: 18px; border: none;')
        self.layout.addWidget(self.content)
        self.setMinimumWidth(480)
    def show_mitre(self, mitre_data):
        html = '<b>Detected Tactics & Techniques:</b><br><ul style="margin-top:10px;">'
        for entry in mitre_data:
            tactic = entry.get('tactic', 'Unknown')
            technique = entry.get('technique', 'Unknown')
            tid = entry.get('id', '')
            tid_link = mitre_link(tid)
            if tid_link:
                tid_html = f'<a href="{tid_link}" style="color:#00BFFF; text-decoration:underline;" title="View on MITRE">{tid}</a>'
            else:
                tid_html = f'<span style="color:#00BFFF;">{tid}</span>'
            html += f'<li style="margin-bottom:10px;"><b style="color:#00BFFF;">{tactic}</b>: <span style="color:#44D362;">{technique}</span> [{tid_html}]</li>'
        html += '</ul>'
        self.content.setHtml(html)
    def show_demo_matrix(self):
        html = '''
        <div style="font-size:20px; color:#AAB2BD; text-align:center; margin-top:16px; font-style:italic;">
            No adversary techniques detected.<br>
            <span style="font-size:16px;">This sample is a mystery to the MITRE ATT&CK matrix.</span>
        </div>
        <div style="margin-top:24px;">
        <table style="width:100%; border-spacing:8px;">
        <tr>
            <td style="background:#232629; border-radius:8px; color:#00BFFF; font-weight:bold; padding:8px 6px;">Initial Access</td>
            <td style="background:#232629; border-radius:8px; color:#44D362; font-weight:bold; padding:8px 6px;">Execution</td>
            <td style="background:#232629; border-radius:8px; color:#FFA500; font-weight:bold; padding:8px 6px;">Persistence</td>
        </tr>
        <tr>
            <td style="background:#232629; border-radius:8px; color:#AAB2BD; padding:6px;">Phishing</td>
            <td style="background:#232629; border-radius:8px; color:#AAB2BD; padding:6px;">PowerShell</td>
            <td style="background:#232629; border-radius:8px; color:#AAB2BD; padding:6px;">Registry Run Keys</td>
        </tr>
        </table>
        </div>
        '''
        self.content.setHtml(html)

class Dashboard(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('SOC Dashboard - Threat Intelligence')
        self.setStyleSheet(self.dark_stylesheet())
        self.setup_ui()
        self.showMaximized()
    def dark_stylesheet(self):
        return '''
        QWidget {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #10131a, stop:1 #1a232a);
            color: #E8EAED;
            font-family: "Segoe UI", "Roboto", Arial, sans-serif;
        }
        QLineEdit, QTableWidget, QHeaderView::section {
            background-color: #232629;
            color: #E8EAED;
            border-radius: 12px;
            border: 2px solid #00BFFF;
        }
        QTableWidget {
            gridline-color: #232629;
            selection-background-color: #232629;
            selection-color: #E8EAED;
        }
        QTableWidget QTableCornerButton::section {
            background: #232629;
        }
        QHeaderView::section {
            background-color: #232629;
            color: #00BFFF;
            font-weight: bold;
            font-size: 20px;
            border-radius: 12px;
            border: 2px solid #00BFFF;
            padding: 10px;
        }
        QPushButton {
            background-color: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #00BFFF, stop:1 #44D362);
            color: #181A1B;
            border-radius: 12px;
            font-size: 20px;
            font-weight: bold;
            padding: 10px 32px;
            margin-left: 8px;
        }
        QPushButton:hover {
            background-color: #005A9E;
            color: #fff;
        }
        QLineEdit {
            font-size: 20px;
            padding: 10px;
        }
        QLabel {
            font-size: 20px;
        }
        '''
    def setup_ui(self):
        main_layout = QVBoxLayout()
        title = QLabel('Threat Intelligence Dashboard')
        title.setStyleSheet('font-size: 48px; font-weight: bold; color: #00BFFF; margin-bottom: 8px; letter-spacing:2px;')
        main_layout.addWidget(title, alignment=Qt.AlignCenter)
        motto = QLabel('SOC Efficiency, Supercharged.')
        motto.setStyleSheet('font-size: 24px; font-weight: bold; color: #44D362; margin-bottom: 24px; font-family: "Segoe UI", "Roboto", Arial, sans-serif; letter-spacing: 1px;')
        main_layout.addWidget(motto, alignment=Qt.AlignCenter)
        input_row = QHBoxLayout()
        self.input_box = QLineEdit()
        self.input_box.setPlaceholderText('Enter file hash or IP address...')
        self.input_box.setMinimumWidth(500)
        self.input_box.setStyleSheet('font-size: 22px;')
        search_btn = QPushButton('Search')
        search_btn.setStyleSheet('font-size: 22px;')
        search_btn.clicked.connect(self.on_search)
        input_row.addWidget(self.input_box)
        input_row.addWidget(search_btn)
        main_layout.addLayout(input_row)
        split = QHBoxLayout()
        verdicts_layout = QVBoxLayout()
        self.vt_result_label = QLabel('')
        self.vt_result_label.setStyleSheet('font-size: 28px; margin-top: 24px; font-weight: bold; color:#00BFFF;')
        verdicts_layout.addWidget(self.vt_result_label, alignment=Qt.AlignLeft)
        self.vt_table = QTableWidget()
        self.vt_table.setColumnCount(3)
        self.vt_table.setHorizontalHeaderLabels(['Engine/Site', 'Verdict', 'Source'])
        self.vt_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.vt_table.setStyleSheet('font-size: 18px; border-radius: 12px;')
        self.vt_table.hide()
        verdicts_layout.addWidget(self.vt_table)
        split.addLayout(verdicts_layout, 2)
        self.mitre_panel = MitrePanel()
        split.addWidget(self.mitre_panel, 1)
        main_layout.addLayout(split)
        info = QLabel('\nClick an engine name to open its scan page (if supported).')
        info.setStyleSheet('font-size: 16px; color: #AAB2BD; margin-top: 30px;')
        main_layout.addWidget(info, alignment=Qt.AlignCenter)
        self.setLayout(main_layout)
    def on_search(self):
        query = self.input_box.text().strip()
        if not query:
            QMessageBox.warning(self, 'Input Error', 'Please enter a file hash or IP address.')
            return
        self.vt_result_label.setText('Searching VirusTotal & Hybrid Analysis...')
        self.vt_table.hide()
        self.mitre_panel.show_demo_matrix()
        QApplication.processEvents()
        vt_result, vt_status, vt_engines = self.query_virustotal(query)
        ha_result, ha_status, ha_engines, mitre_data = self.query_hybrid_analysis(query)
        engines = vt_engines + ha_engines
        summary_color = {
            'malicious': '#FF5555',
            'harmless': '#44D362',
            'suspicious': '#FFA500',
            'unknown': '#AAB2BD'
        }.get(vt_status if vt_status != 'unknown' else ha_status, '#AAB2BD')
        summary_icon = {
            'malicious': '✖',
            'harmless': '✔',
            'suspicious': '⚠',
            'unknown': '?'
        }.get(vt_status if vt_status != 'unknown' else ha_status, '?')
        self.vt_result_label.setStyleSheet(f'font-size: 28px; margin-top: 24px; font-weight: bold; color: {summary_color}; background: #232629; border-radius: 12px; padding: 18px 32px;')
        self.vt_result_label.setText(f"{summary_icon} {vt_result}\n{ha_result}")
        if engines:
            self.vt_table.setRowCount(len(engines))
            self._engine_links = []
            for i, (engine, verdict, link, clickable, source) in enumerate(engines):
                engine_item = QTableWidgetItem(engine)
                engine_item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
                font = QFont()
                if clickable:
                    font.setUnderline(True)
                    engine_item.setFont(font)
                    engine_item.setForeground(QColor('#00BFFF'))
                    engine_item.setToolTip(f'Open {engine} scan page')
                else:
                    font.setUnderline(False)
                    engine_item.setFont(font)
                    engine_item.setForeground(QColor('#E8EAED'))
                    engine_item.setToolTip('No direct search available for this engine')
                verdict_display = verdict if verdict and verdict.lower() not in ['','none','null'] else 'Unknown'
                icon, chip_color = verdict_chip(verdict_display)
                verdict_item = QTableWidgetItem(f"{icon} {verdict_display.capitalize()}")
                verdict_item.setFlags(Qt.ItemIsEnabled)
                verdict_item.setTextAlignment(Qt.AlignCenter)
                verdict_item.setForeground(chip_color)
                source_item = QTableWidgetItem(source)
                source_item.setFlags(Qt.ItemIsEnabled)
                source_item.setForeground(QColor('#AAB2BD'))
                self.vt_table.setItem(i, 0, engine_item)
                self.vt_table.setItem(i, 1, verdict_item)
                self.vt_table.setItem(i, 2, source_item)
                self._engine_links.append(link if clickable else None)
            self.vt_table.resizeRowsToContents()
            self.vt_table.show()
            self.vt_table.cellClicked.connect(self.on_engine_click)
        else:
            self.vt_table.hide()
        if mitre_data:
            self.mitre_panel.show_mitre(mitre_data)
        else:
            self.mitre_panel.show_demo_matrix()
    def on_engine_click(self, row, col):
        if col == 0 and hasattr(self, '_engine_links'):
            link = self._engine_links[row]
            if link:
                webbrowser.open(link)
    def query_virustotal(self, query):
        headers = {"x-apikey": VT_API_KEY}
        url = f"https://www.virustotal.com/api/v3/files/{query}"
        r = requests.get(url, headers=headers)
        engines = []
        if r.status_code == 200:
            data = r.json().get('data', {})
            attr = data.get('attributes', {})
            stats = attr.get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total = sum(stats.values())
            last_analysis_results = attr.get('last_analysis_results', {})
            for engine, result in last_analysis_results.items():
                verdict = result.get('category', '').capitalize() or 'Unknown'
                link = get_engine_link(engine, query)
                clickable = link is not None
                engines.append((engine, verdict, link, clickable, 'VirusTotal'))
            if total > 0:
                if malicious > 0:
                    status = 'malicious'
                elif suspicious > 0:
                    status = 'suspicious'
                else:
                    status = 'harmless'
                result = f"VirusTotal: {malicious}/{total} engines flagged as malicious"
            else:
                result = "VirusTotal: No results found."
                status = 'unknown'
            return result, status, engines
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{query}"
        r = requests.get(url, headers=headers)
        if r.status_code == 200:
            data = r.json().get('data', {})
            attr = data.get('attributes', {})
            stats = attr.get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total = sum(stats.values())
            last_analysis_results = attr.get('last_analysis_results', {})
            for engine, result in last_analysis_results.items():
                verdict = result.get('category', '').capitalize() or 'Unknown'
                link = get_engine_link(engine, query)
                clickable = link is not None
                engines.append((engine, verdict, link, clickable, 'VirusTotal'))
            if total > 0:
                if malicious > 0:
                    status = 'malicious'
                elif suspicious > 0:
                    status = 'suspicious'
                else:
                    status = 'harmless'
                result = f"VirusTotal: {malicious}/{total} engines flagged as malicious"
            else:
                result = "VirusTotal: No results found."
                status = 'unknown'
            return result, status, engines
        return "VirusTotal: No results found.", 'unknown', []
    def query_hybrid_analysis(self, query):
        headers = {
            'api-key': HA_API_KEY,
            'User-Agent': 'Falcon Sandbox',
        }
        url = f'https://www.hybrid-analysis.com/api/v2/search/hash'
        r = requests.post(url, headers=headers, json={"hash": query})
        engines = []
        mitre_data = []
        if r.status_code == 200 and r.json():
            data = r.json()[0]
            verdict = data.get('threat_score', 0)
            verdict_str = 'Malicious' if verdict >= 85 else ('Suspicious' if verdict >= 50 else 'Harmless')
            engines.append(('Hybrid Analysis', verdict_str, None, False, 'Hybrid Analysis'))
            mitre = data.get('mitre_attcks', [])
            for entry in mitre:
                mitre_data.append({
                    'tactic': entry.get('tactic', 'Unknown'),
                    'technique': entry.get('technique', 'Unknown'),
                    'id': entry.get('id', '')
                })
            return f"Hybrid Analysis: Threat Score {verdict}/100", 'malicious' if verdict >= 85 else ('suspicious' if verdict >= 50 else 'harmless'), engines, mitre_data
        else:
            return "Hybrid Analysis: No results found.", 'unknown', [], []

if __name__ == '__main__':
    app = QApplication(sys.argv)
    dashboard = Dashboard()
    sys.exit(app.exec_()) 