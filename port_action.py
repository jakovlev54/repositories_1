#!/usr/bin/python3
from prometheus_api_client import MetricsList, PrometheusConnect
from prometheus_api_client.utils import parse_datetime
import pymysql
import datetime
import re
from json import dumps, loads
from configparser import ConfigParser
from ncclient import manager
import time
from netmiko import ConnectHandler
from pyArango.connection import Connection as Arango_connect


config_script = ConfigParser()
config_script.read('/etc/config_inventory.ini')

PROMETHEUS_ENDPOINT = config_script['PROMETHEUS']['endpoint']
LOAD_THRESHOLD = 90
DB_SERVER = config_script['MYSQL']['address']
DB_USER = config_script['MYSQL']['username']
DB_PASSWORD = config_script['MYSQL']['password']
DEBUG = False  # в режиме дебага изменения не коммитятся
# в режиме этого debug игнорирует если на узле нет накопления ошибок
DEBUG_LAST_CHECKING = False

messages = []
commited_commands = dict()


def checking_core_bundle(host, bundle):
    """ if core bundle - return JSON-bundle from ArangoDB """
    print('Checking trunkPort', flush=True)
    db_arango = Arango_connect(username=DB_USER,
                               password=DB_PASSWORD)["inventory"]
    aql = f"""
    LET host = 'tp/{host}'
    LET port = '{bundle}'
    FOR link in links
        FILTER link['_from'] == host
        FILTER link['int_from'] == port
        RETURN link   
    """
    edge = list(db_arango.AQLQuery(aql, rawResults=True))
    edge = edge[0] if len(edge) == 1 else {}
    return edge


def search_alterWay(lo_ip, host, port, bundle):
    alterway = 0
    print('Search AlterWay... ', flush=True)

    alterway = 1  # пока нет алгоритма поиска
    if alterway == 1:
        messages.append("alternative way not confirmed")
    else:
        messages.append("alternative way not confirmed")
    return alterway


def last_checking(lo_ip, host, port, bundle, messages):
    """ If confirmed problem - return 1, else - return 0 """
    print('Last checking before off... ', flush=True)
    confirm = 0
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
            messages.append(f"request on {lo_ip}: show interfaces {port}")
            int_info = conn.command(
                command=f'show interfaces {port}', format='json')
            int_info = loads(int_info.xpath('.')[0].text)
            bit_errors = int(int_info["interface-information"][0]["physical-interface"]
                             [0]["ethernet-pcs-statistics"][0]["bit-error-seconds"][0]["data"])
            block_errors = int(int_info["interface-information"][0]["physical-interface"]
                               [0]["ethernet-pcs-statistics"][0]["errored-blocks-seconds"][0]["data"])
            last_flapped_msk = int_info["interface-information"][0]["physical-interface"][0]["interface-flapped"][0]["data"].split(' ')[
                :2]
            time.sleep(5)
            int_info = conn.command(
                command=f'show interfaces {port}', format='json')
            int_info = loads(int_info.xpath('.')[0].text)
            diff_bit_errors = (int(int_info["interface-information"][0]["physical-interface"]
                               [0]["ethernet-pcs-statistics"][0]["bit-error-seconds"][0]["data"]) - bit_errors)/5
            diff_block_errors = (int(int_info["interface-information"][0]["physical-interface"][0]
                                 ["ethernet-pcs-statistics"][0]["errored-blocks-seconds"][0]["data"]) - block_errors)/5
            messages.append(
                f"accum bit errors= {diff_bit_errors}b/s, accum block errors= {diff_block_errors}block/s, last flapped = {' '.join(last_flapped_msk)}MSK")
            if diff_bit_errors > 0 or diff_block_errors > 0 or DEBUG_LAST_CHECKING:
                confirm = 1
            messages.append(
                f"request on {lo_ip}: show conf protocols isis interface {bundle['int_from']}")
            int_isis = conn.command(
                command=f"show conf protocols isis interface {bundle['int_from']}", format='text')
            int_isis = int_isis.xpath(
                './configuration-information/configuration-output')[0].text
            metric = int(
                re.search(r'metric (?P<metric>\d{1,8});', int_isis).group('metric'))
            messages.append(f"level 2 metric {metric}")
            if metric != bundle['metric']:
                bundle['metric'] = metric
                messages.append(f' metric changed already today ({metric})')
                confirm = 0

            conn.close_session()
        else:
            messages.append(f' not connect to {lo_ip}')
    except Exception as err:
        messages.append(f' problems in rpc-requests to {lo_ip}')
        print(err, flush=True)
    finally:
        if confirm == 1:
            messages.append("last checked is successfull")
        else:
            messages.append("last checked is failed, Need help of Operator")
        return confirm


def disable_port(lo_ip, host, port, bundle, messages, commited_commands):
    """ If port disabled - return 1, if port active - return 0  """
    action = 0

    command = f"set interfaces {port} disable"

    ssh = {
        "device_type": "juniper",
        "host": lo_ip,
        "username": config_script['XRING_EDIT']['username'],
        "password": config_script['XRING_EDIT']['password'],
        "timeout": 120
    }
    connect_jun = ConnectHandler(**ssh)
    print(lo_ip, ' connected for edit')
    messages.append(f"push on {lo_ip}: {command}")
    try:
        if not DEBUG:
            connect_jun.config_mode(config_command='configure exclusive')
            if connect_jun.check_config_mode():
                connect_jun.send_command(command)
                connect_jun.commit(
                    comment=f'SkyNet disable {port}', and_quit=True)
                action = 1
                messages.append(f"commited on {lo_ip}")
                commited_commands[host] = [command, ]
    except Exception:
        print('error commit')
    connect_jun.disconnect()

    if action == 1:
        messages.append(f"port DOWN on {lo_ip}")
    else:
        messages.append(f"port not DOWN on {lo_ip}, Need help of Operator")
    return action


def port_out_bundle(lo_ip, host, port, bundle, messages, commited_commands):
    """ If port disabled - return 1, if port active - return 0  """
    action = 0

    command = f"deactivate interfaces {port} gigether-options 802.3ad"

    ssh = {
        "device_type": "juniper",
        "host": lo_ip,
        "username": config_script['XRING_EDIT']['username'],
        "password": config_script['XRING_EDIT']['password'],
        "timeout": 120
    }
    connect_jun = ConnectHandler(**ssh)
    print(lo_ip, ' connected for edit')
    messages.append(f"push on {lo_ip}: {command}")
    try:
        if not DEBUG:
            connect_jun.config_mode(config_command='configure exclusive')
            if connect_jun.check_config_mode():
                connect_jun.send_command(command)
                connect_jun.commit(
                    comment=f'SkyNet deactivate {port} gigether-options 802.3ad', and_quit=True)
                action = 1
                messages.append(f"commited on {lo_ip}")
                commited_commands[host] = [command, ]
    except Exception:
        print('error commit')
    connect_jun.disconnect()

    if action == 1:
        messages.append(f"port removed from bundle on {lo_ip}")
    else:
        messages.append(
            f"port not removed from bundle on {lo_ip}, Need help of Operator")
    return action


def metric_increasing(lo_ip, host, port, bundle, messages, commited_commands):
    """ If metrik increesed - return 1, else - return 0  """
    print('Increasing metric...', flush=True)
    action = 0
    metric_new = str(65000 + bundle['metric'])

    # Меняем метрику на ближнем узле (в приватном режиме)
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
                command = f"set protocols isis interface {bundle['int_from']} level 2 metric {metric_new}"
                messages.append(f"push on {lo_ip}: {command}")
                connect_jun.send_command(command)
                connect_jun.commit(
                    comment=f"SkyNet {bundle['int_from']} metric->{metric_new}", and_quit=True)
                messages.append(f"commited on {lo_ip}")
                commited_commands[host] = [command, ]
                command = f"set protocols mpls interface {bundle['int_from']} switch-away-lsps"
                messages.append(f"push on {lo_ip}: {command}")
                connect_jun.send_command(command)
                connect_jun.commit(
                    comment=f"SkyNet {bundle['int_from']} switch-away-lsps", confirm=True, confirm_delay=1)
                messages.append(f"commit confirmed 1 on {lo_ip}")
                action = 2
    except Exception:
        print('error commit')
        messages.append(f"metric increasing not commited on {lo_ip}")
    connect_jun.disconnect()

    # меняем метрику на дальнем узле (в приватном режиме)
    host_to = bundle['_to'].split('/')[1]
    lo_ip_to = '10.249.' + host_to.split('-')[0].replace('TP', '')
    ssh = {
        "device_type": "juniper",
        "host": lo_ip_to,
        "username": config_script['XRING_EDIT']['username'],
        "password": config_script['XRING_EDIT']['password'],
        "timeout": 120
    }
    connect_jun = ConnectHandler(**ssh)
    print(lo_ip_to, ' connected for edit')
    try:
        if not DEBUG and action == 2:
            connect_jun.config_mode(config_command='configure exclusive')
            if connect_jun.check_config_mode():
                command = f"set protocols isis interface {bundle['int_to']} level 2 metric {metric_new}"
                messages.append(f"push on {lo_ip_to}: {command}")
                connect_jun.send_command(command)
                connect_jun.commit(
                    comment=f"SkyNet {bundle['int_to']} metric->{metric_new}", and_quit=True)
                messages.append(f"commited on {lo_ip_to}")
                commited_commands[host_to] = [command, ]
                command = f"set protocols mpls interface {bundle['int_to']} switch-away-lsps"
                messages.append(f"push on {lo_ip_to}: {command}")
                connect_jun.send_command(command)
                connect_jun.commit(
                    comment=f"SkyNet {bundle['int_to']} switch-away-lsps", confirm=True, confirm_delay=1)
                messages.append(f"commit confirmed 1 on {lo_ip_to}")
                action = 2
    except Exception:
        print('error commit')
        messages.append(f"metric increasing not commited on {lo_ip_to}")
        action = 0
    connect_jun.disconnect()

    return action


def checking_bundle_and_to_interface_SQL(host, port):
    """ If bundle is not exist - return port+unit  """
    db = pymysql.connect(host=DB_SERVER, user=DB_USER,
                         password=DB_PASSWORD, db='inventory')
    with db.cursor() as cursor:
        sql = "SELECT bundle, subinterface, description FROM interfaces WHERE interface=%s AND hostname=%s"
        cursor.execute(sql, (port, host))
        result = cursor.fetchall()[0]
        bundle = result[0]+'.0' if result[0] else port+'.'+result[1]
        interface_to = result[2].split('_')[1]
    db.close()
    return (bundle, interface_to)


def createEntry_in_SQLdb(action_result):
    db = pymysql.connect(host=DB_SERVER, user=DB_USER,
                         password=DB_PASSWORD, db='inventory')
    with db.cursor() as cursor:
        sql = "INSERT INTO auto_deact_interf (time, hostname, interface,"\
              " bundle, state, util_percent, description)" \
              " VALUES (%s, %s, %s, %s, %s, %s, %s)"
        cursor.execute(sql, (datetime.datetime.utcnow(), action_result['resource'].split(':')[0],
                             action_result['resource'].split(
                                 ':')[1], action_result['bundle']['int_from'],
                             action_result['action'], action_result['r_util_percent'], dumps(action_result)))
        db.commit()
    db.close()
    return 1


def get_interface_avg_load(host, interface, last_period='5m'):
    pc = PrometheusConnect(url=PROMETHEUS_ENDPOINT, disable_ssl=True)
    # start_time = parse_datetime(last_period)
    # end_time = parse_datetime("now")
    metric_data_rx = pc.custom_query(
        'avg_over_time(interface_rx:rate_1m:percentage{' +
        'system_id="' + host + '",name="' + interface + '"}[' + last_period + '])')
    metric_data_tx = pc.custom_query(
        'avg_over_time(interface_tx:rate_1m:percentage{' +
        'system_id="' + host + '",name="' + interface + '"}[' + last_period + '])')
    return (float(metric_data_rx[0]['value'][1]),
            float(metric_data_tx[0]['value'][1]))


def get_bundle_avg_load(host, bundle, last_period='5m'):
    """ Average load of bundle  """
    pc = PrometheusConnect(url=PROMETHEUS_ENDPOINT, disable_ssl=True)
    labels = 'system_id=\'' + host + \
        '\',interface_state_parent_ae_name=\'' + bundle + '\''
    metric_data_rx = pc.custom_query(
        'avg_over_time(ae_rx:rate_1m{' + labels + '}[' + last_period + '])')
    metric_data_tx = pc.custom_query(
        'avg_over_time(ae_tx:rate_1m{' + labels + '}[' + last_period + '])')
    return (float(metric_data_rx[0]['value'][1]),
            float(metric_data_tx[0]['value'][1]))


def get_interface_optics(host, interface):
    pc = PrometheusConnect(url=PROMETHEUS_ENDPOINT, disable_ssl=True)
    # start_time = parse_datetime(last_period)
    # end_time = parse_datetime("now")
    optics_rx_avg_2h = pc.custom_query(
        'min(avg_over_time(interfaces_interface_optics_lanediags_lane_lane_laser_receiver_power_dbm{system_id="'+host+'", name="'+interface+'"}[4h]))')
    optics_rx_min_5m = pc.custom_query(
        'min(min_over_time(interfaces_interface_optics_lanediags_lane_lane_laser_receiver_power_dbm{system_id="'+host+'", name="'+interface+'"}[5m]))')
    return (float(optics_rx_avg_2h[0]['value'][1]),
            float(optics_rx_min_5m[0]['value'][1]))


def get_bundle_restricted_bw(host, bundle, port):
    """ Checking BW(bundle)-BW(port) """
    pc = PrometheusConnect(url=PROMETHEUS_ENDPOINT, disable_ssl=True)
    bw = pc.custom_query('ae_bandwidth{system_id="' + host +
                         '",interface_state_parent_ae_name="' + bundle +
                         '"} - on(system_id,interface_state_parent_ae_name)' +
                         'interfaces_interface_state_high_speed{system_id="' +
                         host + '",name="' + port + '"}')
    return (int(bw[0]['value'][1]) * 1000000)


def get_bundle_members(host, bundle):
    pc = PrometheusConnect(url=PROMETHEUS_ENDPOINT, disable_ssl=True)
    bw = pc.custom_query('junos:interface_rx:rate_2m{system_id="' +
                         host + '",_interfaces_interface_state_parent_ae_name="' +
                         bundle + '"}')
    return bw


def resolver_flappingANDerror_TrunkPort_fsm(id, event, host, port, flag_history, logger):
    try:
        flag_of_action = 0
        flag_of_loss_optic = 0
        r_util_percent = None
        lo_ip = '10.249.' + \
            re.match(
                r"^(?P<hostname>TP(?P<ip>\d{1,3}\.\d{1,3})-[^-]{2,8}-[A-Z]{2,4}(-\w{1,8})?)$", host).group('ip')
        # если порт не в агрегате, в бандле запишется логический интерфейс
        bundle, interface_to = checking_bundle_and_to_interface_SQL(host, port)
        # здесь уже json объект о бандле
        bundle = checking_core_bundle(host, bundle)
        # если агрегат клиентский, просто сообщение
        if bundle == {}:
            messages.append('Error client port on X-Ring')

        # ЛИНК ТРАНКОВЫЙ И В АГРЕГАТЕ
        elif bundle['int_from'].split('.')[0] != port:
            host_to = bundle['_to'].split('/')[1]
            # проверка дрожания оптики на интерфейсах с двух сторон линка за последние 5 минут
            optic_from_avg, optic_from_curr = get_interface_optics(host, port)
            if optic_from_avg - optic_from_curr > 0.5:
                flag_of_loss_optic = 1
                messages.append(
                    f'interface loss of optic signal = {round(optic_from_avg - optic_from_curr, 2)} dB')
            optic_to_avg, optic_to_curr = get_interface_optics(
                host_to, interface_to)
            if optic_to_avg - optic_to_curr > 0.5:
                flag_of_loss_optic = 1
                messages.append(
                    f'interface {interface_to} on {host_to} loss of optic signal = {round(optic_to_avg - optic_to_curr, 2)} dB')
            if flag_of_loss_optic == 0:
                messages.append('optical power is stable on both sides')

            r_bw = get_bundle_restricted_bw(
                host, bundle['int_from'].split('.')[0], port)

            if r_bw > 0:  # если не единственный в агрегате
                r_util_percent = round(max(get_bundle_avg_load(
                    host, bundle['int_from'].split('.')[0], '15m')) / r_bw * 100, 2)
                messages.append(
                    f'if port disable bundle utilization = {r_util_percent} %')
                if r_util_percent < LOAD_THRESHOLD:  # если утилизация без линка в бандле меньше порога

                    # если истории по этому случаю нет
                    if flag_history == 0:

                        # последняя проверка перед выключением линка
                        if last_checking(lo_ip, host, port, bundle, messages) == 1:

                            # отключение линка
                            flag_of_action = disable_port(lo_ip, host, port,
                                                          bundle, messages,
                                                          commited_commands)
                    # если порт уже пробовали отключать-включать
                    elif flag_history == -1:

                        # вывод порта из бандла
                        flag_of_action = port_out_bundle(lo_ip, host, port,
                                                         bundle, messages,
                                                         commited_commands)

                else:  # если утилизация без линка в бандле больше порога
                    messages.append("High bundle utilization")

                    # ищем наличие альтернативных путей
                    if search_alterWay(lo_ip, host, port, bundle) == 1:

                        # последняя проверка перед загрублением метрики
                        if last_checking(lo_ip, host, port, bundle, messages) == 1:

                            # загрубляем метрику
                            flag_of_action = metric_increasing(lo_ip, host, port,
                                                               bundle, messages,
                                                               commited_commands)

                    else:  # если нет альтернативных путей

                        # последняя проверка перед загрублением метрики
                        if last_checking(lo_ip, host, port, bundle, messages) == 1:

                            # загрубляем метрику
                            flag_of_action = metric_increasing(lo_ip, host, port,
                                                               bundle, messages,
                                                               commited_commands)

            else:  # ЛИНК ТРАНКОВЫЙ И ОДИН В АГРЕГАТЕ
                messages.append("Single port in bundle")
                r_util_percent = round(
                    max(get_interface_avg_load(host, port))*100, 2)
                messages.append(f'bundle utilization = {r_util_percent} %')
                # ищем наличие альтернативных путей
                if search_alterWay(lo_ip, host, port, bundle) == 1:

                    # последняя проверка перед загрублением метрики
                    if last_checking(lo_ip, host, port, bundle, messages) == 1:

                        # загрубляем метрику
                        flag_of_action = metric_increasing(lo_ip, host, port,
                                                           bundle, messages,
                                                           commited_commands)

                else:  # если нет альтернативных путей
                    messages.append("alterWay not exist")

                    # последняя проверка перед загрублением метрики
                    if last_checking(lo_ip, host, port, bundle, messages) == 1:

                        # загрубляем метрику
                        flag_of_action = metric_increasing(lo_ip, host, port,
                                                           bundle, messages,
                                                           commited_commands)

        else:  # ЛИНК ТРАНКОВЫЙ И НЕ В АГРЕГАТЕ
            messages.append("Port not in bundle")
            host_to = bundle['_to'].split('/')[1]
            # проверка дрожания оптики на интерфейсах с двух сторон линка за последние 5 минут
            optic_from_avg, optic_from_curr = get_interface_optics(host, port)
            if optic_from_avg - optic_from_curr > 0.5:
                flag_of_loss_optic = 1
                messages.append(
                    f'interface loss of optic signal = {round(optic_from_avg - optic_from_curr, 2)} dB')
            optic_to_avg, optic_to_curr = get_interface_optics(
                host_to, interface_to)
            if optic_to_avg - optic_to_curr > 0.5:
                flag_of_loss_optic = 1
                messages.append(
                    f'interface {interface_to} on {host_to} loss of optic signal = {round(optic_to_avg - optic_to_curr, 2)} dB')
            if flag_of_loss_optic == 0:
                messages.append('optical power is stable on both sides')

            r_util_percent = round(
                max(get_interface_avg_load(host, port))*100, 2)
            messages.append(f'interface utilization = {r_util_percent} %')
            # ищем наличие альтернативных путей
            if search_alterWay(lo_ip, host, port, bundle) == 1:

                # последняя проверка перед загрублением метрики
                if last_checking(lo_ip, host, port, bundle, messages) == 1:

                    # загрубляем метрику
                    flag_of_action = metric_increasing(lo_ip, host, port,
                                                       bundle, messages,
                                                       commited_commands)

            else:  # если нет альтернативных путей

                # последняя проверка перед загрублением метрики
                if last_checking(lo_ip, host, port, bundle, messages) == 1:

                    # загрубляем метрику
                    flag_of_action = metric_increasing(lo_ip, host, port,
                                                       bundle, messages,
                                                       commited_commands)

        action_result = {
            'id': id,
            'event': event,
            'messages': messages,
            'bundle': bundle,
            'resource': host + ':' + port,
            'action': flag_of_action,
            'r_util_percent': r_util_percent,
            'commited_commands': commited_commands
        }
        createEntry_in_SQLdb(action_result)
    except Exception as err:
        logger.error(err, messages)
    return action_result


if __name__ == '__main__':
    print('main')
