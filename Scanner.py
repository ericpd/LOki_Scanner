#!/usr/bin/python3

#===============================================================================
#  Name        : LOki_Scanner.py
#  Author      : Free programmer
#  Version     : v2.2
#  Copyright   : Your copyright notice
#  Description : Central IoC collector based on Loki IoC scanner
#===============================================================================

import sys
import os
import socketserver
import http.server
import psutil #check established connections
import json #check latest loki
import urllib.request #check latest loki
import configparser
from zipfile import ZipFile
from pyparsing import Word, alphas, Suppress, Combine, nums, Regex
import csv
from PyQt5 import QtCore, QtGui, QtWidgets, uic
from PyQt5.QtCore import QObject, QThread, pyqtSignal
from PyQt5.QtCore import QTimer
from PyQt5.QtWidgets import QFileDialog, QTableWidgetItem


# python3 loki.py -r listener_ip -t listener_port --syslogtcp --onlyrelevant  --nolog


### define absolute paths ####
form_path = os.path.join(os.path.dirname(__file__), "Scanner.ui")
configuration_file = os.path.join(os.path.dirname(__file__), "config.cfg")
http_dir = os.path.join(os.path.dirname(__file__), "web")
loki_zip = os.path.join(os.path.dirname(__file__), "web", "loki.zip")
qtCreatorFile = form_path # UI file here.
Ui_MainWindow, QtBaseClass = uic.loadUiType(qtCreatorFile)
########################################

### configurations and initialisations###
config = configparser.ConfigParser()
config.read(configuration_file)
HOST_LISTENER = config['general']['listener_host']
PORT_LISTENER = int(config['general']['listener_port'])
HOST_HTTP = config['general']['http_host']
PORT_HTTP = int(config['general']['http_port'])
LOKI_URL = config['general']['loki_url']
feed = None
########################################

### Class to init the listener ###
class ThreadedTCPHandler(socketserver.ThreadingMixIn, socketserver.BaseRequestHandler):
    daemon_threads = True
    def handle(self):
        global feed
        self.data = self.request.recv(1024).strip().decode('utf-8')
        feed = "IP:" + self.client_address[0] + self.data
########################################

### Class to init the http server ###
class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.SimpleHTTPRequestHandler):
    daemon_threads = True
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=http_dir, **kwargs)
        


### a class to start and stop the listener as a thread ###
class worker_listener(QObject):
    finished = pyqtSignal()
    progress = pyqtSignal(int)
 
    def start(self):
        try:
            socketserver.TCPServer.allow_reuse_address = True
            self.listener = socketserver.TCPServer((HOST_LISTENER, PORT_LISTENER), ThreadedTCPHandler)
            with self.listener as server:
                server.serve_forever()
        except:
            print("Check if address already in use")
        
    def stop(self):
        self.listener.shutdown()
########################################

### a class to start and stop the server as a thread ###
class worker_http(QObject):
    finished = pyqtSignal()
    progress = pyqtSignal(int)
 
    def start(self):
        try:
            socketserver.TCPServer.allow_reuse_address = True
            self.http = socketserver.TCPServer((HOST_HTTP, PORT_HTTP), ThreadedHTTPServer)
            with self.http as httpd:
                httpd.serve_forever()
        except:
            pass
        
    def stop(self):
        self.http.shutdown()
########################################
    
class Parser(object):
    def __init__(self):
        ints = Word(nums)
        
        IP = Suppress("IP:") + Combine(ints + "." + ints + "." + ints + "."  + ints )
        fl = Suppress("<") + ints + Suppress(">") + ints 
        timestamp = Combine(ints + "-" + ints + "-" + ints+ "T" + ints+ ":" + ints + ":" + ints + "." + ints + "-" + ints + ":" + ints)
        hostname = Word(alphas + nums + "_" + "-" + ".")
        mes_type = Suppress("LOKI") + ints +  ints + Suppress("-") +  Suppress("\ufeff") + Suppress("LOKI:") +  Word(alphas)
        module =  Suppress(":") + Suppress("MODULE:") + Word(alphas)
        message = Suppress("MESSAGE:") + Regex(".*")
    
    
  
    # pattern build
        self.__pattern = IP  +fl +  timestamp + hostname + mes_type + module + message 
    # parse logs    
    def parse(self, line):
        parsed = self.__pattern.parseString(line)
                
        payload              = {}
        payload["IP"]  = parsed[0]
        payload["timestamp"] = parsed[3]
        payload["hostname"] = parsed[4]
        payload["mes_type"] = parsed[7]
        payload["module"] = parsed[8]
        payload["message"] = parsed[9]
        
        return payload   
    

class MyWindow(QtWidgets.QMainWindow, Ui_MainWindow, worker_listener, worker_http):
    def __init__(self):
        
        QtWidgets.QMainWindow.__init__(self)
        Ui_MainWindow.__init__(self)
        self.setupUi(self)
        ### check feed every 1 second ###
        timer = QTimer(self)
        timer.timeout.connect(self.check_feed)
        timer.start(1000)
        ########################################
        

        ### configurations textEdit ###
        self.textEdit_5.setPlainText(HOST_LISTENER)
        self.textEdit_6.setPlainText(str(PORT_LISTENER))
        self.textEdit_9.setPlainText(HOST_HTTP)
        self.textEdit_10.setPlainText(str(PORT_HTTP))
        self.textEdit_8.setPlainText(str(LOKI_URL))
        ########################################
        
        ### buttons and signals ###
        self.tabWidget.currentChanged.connect(self.extend_parser_view) # if tab changed
        self.pushButton.clicked.connect(self.start_listener)
        self.pushButton_2.clicked.connect(self.stop_listener)
        self.pushButton_3.clicked.connect(self.save_feed)
        self.pushButton_4.clicked.connect(self.clear_feed)
        self.pushButton_5.clicked.connect(self.get_ip)
        self.pushButton_6.clicked.connect(self.check_loki)
        self.pushButton_7.clicked.connect(self.save_config)
        self.pushButton_8.clicked.connect(self.load_default_powershell)
        self.pushButton_9.clicked.connect(self.save_powershell)
        self.pushButton_10.clicked.connect(self.download_loki)
        self.pushButton_11.clicked.connect(self.start_http)
        self.pushButton_12.clicked.connect(self.stop_http)
        self.pushButton_13.clicked.connect(self.save_csv)
        ########################################
        
    ### check feed from loki clients and parse data to tableWidget ###    
    def check_feed(self):
        global feed
        spaces = 90*"*"
        parser = Parser()
        try:
            if feed:
                self.textEdit.append(feed)
                self.textEdit.append(spaces)
                fields = parser.parse(feed)
                ### start feeding parsed data to tableWidget ###
                self.rowPosition = self.tableWidget.rowCount()
                self.tableWidget.insertRow(self.rowPosition)
                self.tableWidget.setItem(self.rowPosition , 0, QTableWidgetItem(fields["IP"]))
                self.tableWidget.setItem(self.rowPosition , 1, QTableWidgetItem(fields["timestamp"]))
                self.tableWidget.setItem(self.rowPosition , 2, QTableWidgetItem(fields["hostname"]))
                self.tableWidget.setItem(self.rowPosition , 3, QTableWidgetItem(fields["mes_type"]))
                self.tableWidget.setItem(self.rowPosition , 4, QTableWidgetItem(fields["module"]))
                self.tableWidget.setItem(self.rowPosition , 5, QTableWidgetItem(fields["message"]))
                self.tableWidget.resizeColumnsToContents()
                
                feed = None
        except:
            pass
    ########################################
    
    ### creat a thread and call worker_listener to start the listener as a thread ###               
    def start_listener(self):
        self.thread_listener = QThread(parent=self) #Create a QThread object
        self.worker_listener = worker_listener() #Create a worker object
        self.worker_listener.moveToThread(self.thread_listener) #Move worker to the thread
        self.thread_listener.started.connect(self.worker_listener.start) #Connect signals and slots
        self.thread_listener.setTerminationEnabled(True)
        self.thread_listener.start() #Start the thread
        self.thread_listener.wait(1000) # wait to check 
        try:
            if self.worker_listener.listener: #check if the listener is up
                self.pushButton.setEnabled(False)
                self.label_3.setText("Started")
        except:
            print("Check if address already in use")
    ########################################
            
    ### stop the listener and terminate the listener thread ###   
    def stop_listener(self):
        self.worker_listener.stop() #call stop method
        self.thread_listener.quit()
        self.thread_listener.wait()
        self.pushButton.setEnabled(True)
        self.label_3.setText("Stopped") 
    ########################################
    
    ### save feed output ###
    def save_feed(self):
        try:
            file = QFileDialog.getSaveFileName() #save dialog
            text = self.textEdit.toPlainText().encode(encoding='UTF-8')
            with open(str(file[0]), 'wb') as f:
                f.write(text)
        except:
            pass
    ########################################
    
    ### clear feed textEdit ### 
    def clear_feed(self):
        self.textEdit.clear() 
    ########################################
    
    ### get all established connections with the listener ###
    def get_ip(self):
        x = psutil.net_connections(kind='tcp')
        for i in x:
            if len(i[3]) > 0:
                if i[3][1] == PORT_LISTENER:
                    if len(i[4]) > 0 :
                        ip_status = i[4][0] + " " + i[5]
                        self.textEdit_2.setPlainText(ip_status)
                    else:
                        pass
        else:
            pass
    ########################################
       
    ### check loki latest version and provide a download URL ###
    def check_loki(self):
        _json = json.loads(urllib.request.urlopen(urllib.request.Request(
        'https://api.github.com/repos/Neo23x0/Loki/releases/latest',
        headers={'Accept': 'application/vnd.github.v3+json'},
        )).read())
        asset = _json['assets'][0]
        latest_name = urllib.request.urlparse(asset['name'])[2]
        latest_url = urllib.request.url2pathname(asset['browser_download_url'])
        self.textEdit_3.setPlainText(latest_name)
        self.textEdit_4.setPlainText(latest_url)
    ########################################
    
    ### Save configurations in configfile ###
    def save_config(self):
        config['general']['listener_host'] = self.textEdit_5.toPlainText()
        config['general']['listener_port'] = self.textEdit_6.toPlainText()
        config['general']['http_host'] = self.textEdit_9.toPlainText()
        config['general']['http_port'] = self.textEdit_10.toPlainText()
        config['general']['loki_url'] = self.textEdit_8.toPlainText()
        with open(configuration_file, 'w') as configfile:
            config.write(configfile)
    ########################################
    
    ### Load a dafault powershell script to start loki ###    
    def load_default_powershell(self):
        powershell_script= """#Variables
$computername = Get-Content servers.txt
$sourcefile = "\\\\server01\\Pranay\\xxxxx.exe"
#This section will install the software 
foreach ($computer in $computername) 
{
$destinationFolder = "\\\\$computer\\C$\\Temp"
#It will copy $sourcefile to the $destinationfolder. If the Folder does not exist it will create it.

if (!(Test-Path -path $destinationFolder))
{
    New-Item $destinationFolder -Type Directory
}
Copy-Item -Path $sourcefile -Destination $destinationFolder
Invoke-Command -ComputerName $computer -ScriptBlock {Start-Process 'c:\\temp\\xxxxx.exe --update'}
Invoke-Command -ComputerName $computer -ScriptBlock {Start-Process 'c:\\temp\\xxxxxx.exe --exec -r 9080'}
}"""
        self.textEdit_7.setPlainText(powershell_script)
    ########################################
    
    ### save any changes to the powershell script ###
    def save_powershell(self):
        try:
            file = QFileDialog.getSaveFileName() #save dialog
            text = self.textEdit_7.toPlainText().encode(encoding='UTF-8')
            with open(str(file[0]), 'wb') as f:
                f.write(text)
        except:
            pass
    ########################################    
    
    ### Download loki from loki_url in web dir and extract in web dir ###
    def download_loki(self):
        if not os.path.isdir(http_dir):
            os.mkdir(http_dir)
        try:
            urllib.request.urlretrieve(LOKI_URL, loki_zip)
        except:
            print("Could not download Loki")
        try:
            with ZipFile(loki_zip, 'r') as zipObj:
                zipObj.extractall(http_dir)
        except:
            print("Could not extract Loki")
    ########################################    
    
    ### creat a thread and call worker_http to start the http server as a thread ### 
    def start_http(self):
        if not os.path.isdir(http_dir):
            os.mkdir(http_dir)
        self.thread_http = QThread(parent=self) #Create a QThread object
        self.worker_http = worker_http() #Create a worker object
        self.worker_http.moveToThread(self.thread_http) #Move worker to the thread
        self.thread_http.started.connect(self.worker_http.start) #Connect signals and slots
        self.thread_http.setTerminationEnabled(True)
        self.thread_http.start() #Start the thread
        self.thread_http.wait(1000) # wait to check 
        try:
            if self.worker_http.http: #check if the server is up
                self.pushButton_11.setEnabled(False)
                self.label_14.setText("Started")
                
        except:
            print("Check if address already in use")
    ########################################   
    
    ### stop the http server and terminate the http thread ###
    def stop_http(self):
        self.worker_http.stop() #call stop method
        self.thread_http.quit()
        self.thread_http.wait()
        self.pushButton_11.setEnabled(True)
        self.label_14.setText("Stopped")
    ######################################## 
    
    ### export the content of tableWidget to CSV ### 
    def save_csv(self):
        try:
            cvs_file = QFileDialog.getSaveFileName()
            with open(str(cvs_file[0]), 'w') as stream:
                writer = csv.writer(stream)
                for row in range(self.tableWidget.rowCount()):
                    rowdata = []
                    for column in range(self.tableWidget.columnCount()):
                        item = self.tableWidget.item(row, column)
                        if item is not None:
                            rowdata.append(item.text())
                        else:
                            rowdata.append('')
                    writer.writerow(rowdata)
        except:
            print("Something happened while saving CSV file")
    ########################################
    
    ### resize columns to contents ###
    def extend_parser_view(self):
        if self.tabWidget.currentIndex() == 2:
            self.tableWidget.resizeColumnsToContents()
    ########################################
    
      
    
if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = MyWindow()
    window.show()
    sys.exit(app.exec_())

    
    ..
