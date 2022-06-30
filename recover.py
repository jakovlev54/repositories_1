#!/usr/bin/python3
import pymysql
import datetime
import re
from json import dumps, loads
from configparser import ConfigParser
from ncclient import manager
from netmiko import ConnectHandler

config_script = ConfigParser()
config_script.read('/etc/config_inventory.ini')

DB_SERVER = config_script['MYSQL']['address']
DB_USER = config_script['MYSQL']['username']
DB_PASSWORD = config_script['MYSQL']['password']
DEBUG = False  # в режиме дебага изменения не коммитятся
# в режиме этого debug игнорирует если на узле последний коммит чужой
DEBUG_LAST_CHECKING = False
messages = []
commited_commands = dict()


def recover_state_on_junos(host: str, commands: list):
    """
    Pushing delete-commands in Junos routers X-RING.
    Return 1 if successfull, else 0
    """
    action = 0
    lo_ip = '10.249.' + \
        re.match(
            r"^(?P<hostname>TP(?P<ip>\d{1,3}\.\d{1,3})-[^-]{2,8}-[A-Z]{2,4}(-\w{1,8})?)$", host).group('ip')

    ssh = {
        "device_type": "juniper",
        "host": lo_ip,
        "username": config_script['XRING_EDIT']['username'],
        "password": config_script['XRING_EDIT']['password'],
        "timeout": 120
    }
    connect_jun = ConnectHandler(**ssh)
    print(lo_ip, ' connected for edit')
    try:
        if not DEBUG:
            connect_jun.config_mode(config_command='configure exclusive')
            if connect_jun.check_config_mode():
                count = 0
                for command in commands:
                    if re.match(r'^set interfaces [\d\w/-]{6,11} disable$', command):
                        command = command.replace('set ', 'delete ')
                        connect_jun.send_command(command)
                        count += 1
                        messages.append(f"push on {lo_ip}: {command}")
                    if command.find('set protocols isis interface ') == 0:
                        metric = int(command.split(' ')[-1])
                        if metric > 65000:
                            command = command.replace(
                                str(metric), str(metric-65000))
                            connect_jun.send_command(command)
                            count += 1
                            messages.append(f"push on {lo_ip}: {command}")
                        else:
                            messages.append(
                                f"metric less than 65000 on {lo_ip}")
                if count == len(commands):
                    connect_jun.commit(
                        comment=f'SkyNet recover', and_quit=True)
                    action = 1
                    messages.append(f"commited on {lo_ip}")
                    commited_commands[host] = [command, ]
    except Exception:
        print('error commit')
    connect_jun.disconnect()

    if action == 1:
        messages.append(f"state is recover on {lo_ip}")
    else:
        messages.append(f"state not recover on {lo_ip}, Need help of Operator")
    return action


def checking_last_commited_on_host(host):
    """
    checking: if last commit from SkyNet - return 1, else return 0
    """
    check = 0
    lo_ip = '10.249.' + \
        re.match(
            r"^(?P<hostname>TP(?P<ip>\d{1,3}\.\d{1,3})-[^-]{2,8}-[A-Z]{2,4}(-\w{1,8})?)$", host).group('ip')
    try:
        conn = manager.connect(
            host=lo_ip,
            port=830,
            username=config_script['XRING']['username'],
            password=config_script['XRING']['password'],
            timeout=120,
            device_params={'name': 'junos'},
            hostkey_verify=False
        )
        if conn:
            print(lo_ip, 'jun connected', flush=True)
            messages.append(f"request on {lo_ip}: show system commit")
            commits = conn.command(command='show system commit', format='json')
            commits = loads(commits.xpath('.')[0].text)
            try:
                last_commit_user = commits['commit-information'][0]['commit-history'][0]['user'][0]['data']
                last_commit_comment = commits['commit-information'][0]['commit-history'][0]['log'][0]['data']
                if (last_commit_user == 'debug' and
                   last_commit_comment.find('SkyNet')) == 0:
                    check = 1
            except KeyError:
                pass
            conn.close_session()
        else:
            messages.append(f' not connect to {lo_ip}')
    except Exception as err:
        messages.append(f' problems in rpc-requests to {lo_ip}')
        print(err, flush=True)
    finally:
        if DEBUG_LAST_CHECKING:
            check = 1
        if check == 1:
            messages.append(f"last commit from SkyNet on {lo_ip}")
        else:
            messages.append(
                f"checked commits is failed on {lo_ip}, Need help of Operator")
    return check


def createEntryRecover_in_SQLdb(recover_result):
    db = pymysql.connect(host=DB_SERVER, user=DB_USER,
                         password=DB_PASSWORD, db='inventory')
    with db.cursor() as cursor:
        sql = "INSERT INTO auto_deact_interf (time, hostname, interface,"\
              " bundle, state, description)" \
              " VALUES (%s, %s, %s, %s, %s, %s)"
        cursor.execute(sql, (datetime.datetime.utcnow(), recover_result['resource'].split(':')[0],
                             recover_result['resource'].split(
                                 ':')[1], recover_result['bundle']['int_from'],
                             recover_result['action'], dumps(recover_result)))
        db.commit()
    db.close()
    return 1


def recover_state_TrunkPort(action_result):
    """
    If the recover of the Link state was successful, then return in recover_result['action'] -1,
    else return 0
    """
    flag_of_recover = 0
    if action_result['action'] < 1:
        messages.append("there was no action, Need help of Operator")
    else:
        checking = 1
        for host in action_result['commited_commands']:
            checking & checking_last_commited_on_host(host)
        if checking == 0:
            messages.append("checking failed: exist new commits on hosts")
        else:
            recovering = 1
            for host, commands in action_result['commited_commands'].items():
                recovering & recover_state_on_junos(host, commands)
        if recovering == 0:
            messages.append("recovering failed, Need help of Operator")
        else:
            flag_of_recover = 0 - action_result['action']

    recover_result = {
        'id': action_result['id'],
        'event': action_result['event'],
        'messages': messages,
        'bundle': action_result['bundle'],
        'resource': action_result['resource'],
        'action': flag_of_recover,
        'commited_commands': commited_commands
    }
    createEntryRecover_in_SQLdb(recover_result)
    return recover_result


# This is a new line that ends the file
