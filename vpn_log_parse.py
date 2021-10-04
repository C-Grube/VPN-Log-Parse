#!/usr/bin/env python3

###################################################################################################################
##-----------------------------------------------------------------------------------------------------------------
## [Details]:
## This script is designed to run as a daily cron job. It checks the previous day's VPN log file to see if the
## same user ID logs in from more than one country in a 24-hour period. If it does, it will email a chosen recipient
## the details surrounding the suspicious authentication.
##-----------------------------------------------------------------------------------------------------------------
## [Warning]:
## Use at your own risk. I claim no responsibility for the outcome of using this script.
##-----------------------------------------------------------------------------------------------------------------
## [To-Do]:
## Error handling, SMTP authentication, and the ability to use a narrower (or wider) time frame.
## (Instead of the default 24-hour period)
##------------------------------------------------------------------------------------------------------------------
###################################################################################################################

import os
import glob
import re
import requests
import json
import smtplib
import gzip
from collections import Counter

# Gets the .log from the day before
yesterdays_file = sorted(glob.glob('[LOG_PATH]]*.log', recursive=True),
                         key=os.path.getmtime)[-2]


# Self defined GREP function used to pull out IP information from the logs
def grep(pattern, fileObj):
    r = []
    for line in fileObj:
        if re.search(pattern, line):
            r.append(line)
    return r


# Reads the data from yesterday's file
def getData():
    with open(yesterdays_file) as f:
        data = f.readlines()
    return data


# Pulls out the IP, username, time, and geolocation(country) from a successful primary authentication and stores them in a list
def authDetails():
    badList = []
    for log in grep('Primary authentication successful', getData()):
        ip_of_auth = log[log.find('from') + len('for') + 2:-1]
        username = log[log.find('for') + len('for') + 1:log.find('/')]
        time = log[log.find('<134> ') + len('<134> '):log.find('ent-')
            - 2]
        for ip in ip_of_auth.splitlines():
            if not (ip.startswith('10.') or ip.startswith('127.0.0.1')):
                try:
                    send_url = 'http://freegeoip.net/json/' + ip
                    request = requests.get(send_url)
                    j = json.loads(request.text)
                    country_name = j['country_name']
                    badList.append((username, country_name, ip_of_auth,
                                   time))
                except:
                    pass
    return badList


# Checks to see if the same user has logged in from a different country
def getBadLogins():
    results = authDetails()
    tempList = []
    returnList = []
    for i in results:
        for r in results:
            if i[0] == r[0] and i[1] != r[1]:
                tempList.append(i)
    for entry in tempList:
        if entry not in returnList:
            returnList.append(entry)
    return returnList


# Counts the number of times each individual item appears in a list
def listCount(list):
    total = Counter(list)
    return total


# Looks through a specified log file and extracts the machines in which a user started a VPN session from
def getHostNames(username):
    hostname_list = []
    with open(yesterdays_file, 'r') as f:
        data = f.readlines()
        for line in data:
            if username in line and 'hostname' in line:
                hostname = line[line.find('hostname') + 9:line.find('\n'
                        )]
                hostname_list.append(hostname)
    return hostname_list


# Gets a list of usernames from the logs in a specified log directory.
def getUserNames():
    username_list = []
    for log in log_files:
        if log.endswith('.log'):
            with open(log, 'r') as f:
                data = f.readlines()
                for line in data:
                    if 'hostname' in line:
                        user_name = line[line.find(']')
                            + 2:line.find('(')]
                        username_list.append(user_name)
        elif log.endswith('.gz'):
            with gzip.open(log, 'rt', encoding='utf-8') as f:
                data = f.readlines()
                for line in data:
                    if 'hostname' in line:
                        user_name = line[line.find(']')
                            + 2:line.find('(')]
                        username_list.append(user_name)
    return username_list


# Pulls out the hostnames from which a specified user started a VPN session. Accepts a single user as input
def singleUserSearch(user_name):
    host_list = getHostNames(user_name)
    counted = listCount(host_list)
    return counted


# Returns a dictionary that consists of the machines that a "suspicious" user started a VPN tunnel from
def usernameMachineSearch():
    user_name_list = []
    machines_dict = {}
    results_dict = {}
    for user in getBadLogins():
        if user[0] not in user_name_list:
            results_dict.update({user[0]: singleUserSearch(user[0])})
            user_name_list.append(user)

    return results_dict


# If there are any suspicious logins to the VPN it will email the results from the email address you specified. If it finds nothing the program exits
def sendEmail(email_text, email_text2):
    send_to = '[RECIPIENT EMAIL]'
    sender_address = '[SENDER_ADDRESS]'
    smtp_server = smtplib.SMTP('[SMTP_SERVER]', 25)
    suspicious_logins = getBadLogins()
    if suspicious_logins:
        TO = send_to
        SUBJECT = 'NEW SUSPICIOUS VPN AUTHENTICATIONS'
        TEXT = 'Log File = ' + yesterdays_file + '\n' + '\n' + '\n' \
            + str(email_text) + '\n' + '\n' + str(email_text2)
        smtp_server.ehlo()
        BODY = '\r\n'.join(['To: %s' % TO, 'From: %s' % sender_address,
                           'Subject: %s' % SUBJECT, '', TEXT])
        smtp_server.sendmail(sender_address, [TO], BODY)
        smtp_server.quit()
    else:
        TO = send_to
        SUBJECT = 'No New Suspicious VPN Authentications'
        TEXT = 'Log File = ' + yesterdays_file + '\n' + '\n' + '\n' \
            + 'No New Suspicious VPN Authentications Were Found Today'
        smtp_server.ehlo()
        BODY = '\r\n'.join(['To: %s' % TO, 'From: %s' % sender_address,
                           'Subject: %s' % SUBJECT, '', TEXT])
        smtp_server.sendmail(sender_address, [TO], BODY)
        smtp_server.quit()


def main():
    suspicious_auths = getBadLogins()
    get_host_names = usernameMachineSearch()
    sendEmail(suspicious_auths, get_host_names)


if __name__ == '__main__':
    main()
