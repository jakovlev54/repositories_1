#!/usr/bin/python3
"""
                                     %@
                                   %@@@@%
                                 %@@@@@@@@%
                                 @@@@@@@@@@
                              %@   @@@@@@   @%
                            %@@@@   @@@@   @@@@%
                          %@@@@@@@   @@   @@@@@@@%
                        %@@@@@@@@@@      @@@@@@@@@@%
                      %@@@@@@@@@@@@@    @@@@@@@@@@@@@%
                    %@@@@@@@@@@@@@@@    @@@@@@@@@@@@@@@%    
                  %@@@@@@@@@@@@@@@@@    @@@@@@@@@@@@@@@@@%
                %@@@@@@@@@@@@@@@@@@@    @@@@@@@@@@@@@@@@@@@%
              %@@@@@@@@@@@@@@@@@@@@@    @@@@@@@@@@@@@@@@@@@@@%

  ##########################################################################
  #.            .#   ####*  #  ######:  #   %####%  #         ##           #
  #    **********#   =_   -@#  ######:  #  .  %##%  #  #############   #####
  #.             #   *   -###.          #  #+.  %%  #         ######   #####
  #.*********   .#     .@####*******.   #  ####+.   #  #############   #####
  #.............+#   +-   -@#=+.......-##..#####+.  #         ######   #####
  ##########################################################################

Troubleshooting on X-Ring
daemon-process /etc/systemd/system/alerta-troubleshooter.service

restart - sudo systemctl restart alerta-troubleshooter.service
stop - sudo systemctl stop alerta-troubleshooter.service
status - sudo systemctl stop alerta-troubleshooter.service

Logging - /var/log/skynet.log

Write event in MYSQL Inventory table auto_dact_interf

! All commits must be from 'debug' and the word 'SkyNet' in begin comments!

Flag's of action:
     0 - no action
     1 - disable port
     2 - metric increasing (+65000)
     3 - inactive interface 802.3 (if port in bundle)
    -1 - no disable port
    -2 - inverse/decreasing metric( -65000)
    -3 - active interface 802.3 (if port in bundle)

Good luck with that, Leather Bastards.
"""
from sms_send import SMSender
from kombu import BrokerConnection, Exchange, Producer
from kombu.utils.debug import setup_logging
from prometheus_api_client import Metric, MetricsList, PrometheusConnect
from prometheus_api_client.utils import parse_datetime, parse_timedelta
from kombu import Connection, Queue
from kombu.mixins import ConsumerMixin
from alertaclient.models.alert import Alert
import re
from port_action import resolver_flappingANDerror_TrunkPort_fsm
from recover import recover_state_TrunkPort
import datetime
import time
from kombu.utils.debug import setup_logging
import logging
import sys
import threading
import signal
from configparser import ConfigParser
sys.path.append('/opt/scripts/mailer/')
config_sms = ConfigParser()
config_sms.read('/opt/scripts/mailer.alerta.conf')
config_script = ConfigParser()
config_script.read('/etc/config_inventory.ini')

AMQP_URL = config_script['AMQP']['endpoint']
AMQP_TOPIC = "alerta.notify"
PROMETHEUS_ENDPOINT = config_script['PROMETHEUS']['endpoint']
ERRORS = {'InterfaceInErrorsRate': ['critical', ]}
ERRORS_DEBUG = {'test_skynet': ['minor', ]}
CLOSED_SEVERITiES = ['normal', 'ok', 'cleared']
# seconds (hold alert until sending, delete if cleared before end of hold time)
HOLD_TIME = 60
HOLD_TIME_CLOSED = 600
HOLD_TIME_AFTER_ACTION = 86400
# holded alerts (keys - alertid)
on_hold = dict()
# processed alrts (keys - resource)
after_action = dict()


class FanoutPublisher:

    def __init__(self, name=None):
        self.connection = BrokerConnection(AMQP_URL)
        try:
            self.connection.connect()
        except Exception:
            raise RuntimeError

        self.channel = self.connection.channel()
        self.exchange_name = AMQP_TOPIC

        self.exchange = Exchange(
            name=self.exchange_name, type='fanout', channel=self.channel)
        self.producer = Producer(exchange=self.exchange, channel=self.channel)

    def send(self, alert):
        self.producer.publish(alert, declare=[self.exchange], retry=True)


class NetworkManager(threading.Thread):

    def __init__(self):

        self.should_stop = False
        super(NetworkManager, self).__init__()

    def run(self):

        while not self.should_stop:
            for alertid in list(on_hold.keys()):
                try:
                    (alert, hold_time) = on_hold[alertid]
                except KeyError:
                    continue
                if time.time() > hold_time:
                    hostname = re.match(
                        r"^(?P<hostname>TP(?P<ip>\d{1,3}\.\d{1,3})-[^-]{2,8}-[A-Z]{2,4}(-\w{1,8})?):(?P<port>\w{2}-\d{1}/\d{1}/\d{1})$", alert.resource).group('hostname')
                    port = re.match(
                        r"^(?P<hostname>TP(?P<ip>\d{1,3}\.\d{1,3})-[^-]{2,8}-[A-Z]{2,4}(-\w{1,8})?):(?P<port>\w{2}-\d{1}/\d{1}/\d{1})$", alert.resource).group('port')

                    # закрывающие алерты
                    if alert.severity in CLOSED_SEVERITiES:
                        # если закрываемой алерты нет в списке уже обработанных или есть, но не с кодом 1
                        # то удаляем алерту
                        if alert.resource not in after_action or after_action[alert.resource][0]['action'] != 1:
                            logger.info(
                                f"CLOSED {alert.event} / {alert.severity}, host - {hostname}, port - {port} --> DISCARD")
                            try:
                                del on_hold[alertid]
                            except KeyError:
                                pass
                        # если по закрываемой алерте совершались действия на сети
                        # то восстанавливаем состояние и удаляем алерту и корректируем историю по алерте
                        elif after_action[alert.resource][0]['action'] == 1:
                            logger.info(
                                f"CLOSED {alert.event} / {alert.severity}, host - {hostname}, port - {port} --> RECOVER_STATE")
                            recover_result = recover_state_TrunkPort(
                                after_action[alert.resource][0])
                            if recover_result['action'] <= -1:
                                self.escalation(recover_result)
                            try:
                                del on_hold[alertid]
                                after_action[alert.resource] = (
                                    recover_result, time.time() + HOLD_TIME_AFTER_ACTION)
                            except KeyError:
                                continue

                    # открывающие алерты
                    else:
                        # если подобной алерты (узел+порт) нет в истории уже обработанных
                        # включаем Резолвер
                        if alert.resource not in after_action:
                            flag_history = 0
                            logger.info(
                                f"OPEN {alert.event} / {alert.severity}, host - {hostname}, port - {port} --> RESOLVER")
                            action_result = resolver_flappingANDerror_TrunkPort_fsm(
                                alertid+port, alert.event, hostname, port, flag_history, logger)
                            if action_result['action'] >= 1:
                                self.escalation(action_result)
                            after_action[alert.resource] = (
                                action_result, time.time() + HOLD_TIME_AFTER_ACTION)
                        # если такая алерта уже обрабатывалась недавно, и порт отключался
                        # то выводим порт из бандла
                        elif after_action[alert.resource][0]['action'] == -1:
                            flag_history = after_action[alert.resource][0]['action'] == -1
                            logger.info(
                                f"OPEN {alert.event} / {alert.severity}, host - {hostname}, port - {port} --> RESOLVER")
                            action_result = resolver_flappingANDerror_TrunkPort_fsm(
                                alertid+port, alert.event, hostname, port, flag_history, logger)
                            if action_result['action'] >= 1:
                                self.escalation(action_result)
                            after_action[alert.resource] = (
                                action_result, time.time() + HOLD_TIME_AFTER_ACTION)
                        # если такая алерта уже обрабатывалась недавно, и действия другие были
                        # то удаляем
                        else:
                            logger.info(
                                f"OPEN {alert.event} / {alert.severity}, host - {hostname}, port - {port} --> DISCARD")
                            try:
                                del on_hold[alertid]
                            except KeyError:
                                continue

            for alert_resource in list(after_action.keys()):
                try:
                    (action_result, hold_time) = after_action[alert_resource]
                except KeyError:
                    continue
                # история по отработанным алертам очищается через HOLD_TIME_AFTER_ACTION
                if time.time() > hold_time:
                    try:
                        del after_action[alert_resource]
                    except KeyError:
                        pass
            time.sleep(2)

    def escalation(self, action_result):
        publisher = FanoutPublisher()
        action_result['messages'].insert(
            0, f"Reaction on alert {action_result['id'].replace(action_result['resource'].split(':')[1],'')}")
        status = 'open' if action_result['action'] >= 1 else 'closed'
        new_message = {
            "id": action_result['id'],
            "services": "Network",
            "group": "SkyNet",
            "resource": action_result['resource'],
            "event": "TROUBLESHOOTING",  # for debug escalations TROUBLESHOOTING-TEST
            "severity": "major",  # fro debug escalations 'minor'
            "status": status,
            "text": "\n" + "\n".join(action_result['messages']),
            "type": "severity",
            "environment": "Production",
            "origin": action_result['event']
        }
        publisher.send(new_message)
        return


class FanoutConsumer(ConsumerMixin):
    def __init__(self, conn):
        self.connection = conn
        self.channel = self.connection.channel()

    def get_consumers(self, Consumer, channel):
        exchange = Exchange(
            name=AMQP_TOPIC,
            type='fanout',
            channel=self.channel,
            durable=True
        )
        queues = [
            Queue(
                name='',
                exchange=exchange,
                routing_key='',
                channel=self.channel,
                exclusive=True
            )
        ]
        return [
            Consumer(queues=queues, accept=[
                     'json'], callbacks=[self.on_message])
        ]

    def on_message(self, body, message):

        try:
            if body['event'] in list(ERRORS.keys()):
                alert = Alert.parse(body)
                alertid = alert.get_id()
                # здесь алерты только добавляем в заморозку
                if (alertid in on_hold and alert.severity in CLOSED_SEVERITiES):
                    on_hold[alertid] = (alert, time.time() + HOLD_TIME_CLOSED)
                # for debug ERRORS_DEBUG
                if alert.severity in ERRORS[alert.event]:
                    on_hold[alertid] = (alert, time.time() + HOLD_TIME)
            message.ack()

        except Exception as e:
            logger.error(body+'\n'+str(e)+'\n')


if __name__ == '__main__':

    logger = logging.getLogger("Skynet")
    logger.setLevel(logging.INFO)
    fh = logging.FileHandler("/var/log/skynet.log")
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    logger.info("###################################################")
    logger.info("Start Skynet")

    try:
        manager = NetworkManager()
        manager.start()
    except (SystemExit, KeyboardInterrupt):
        sys.exit(0)
    except Exception as e:
        print(str(e))
        sys.exit(1)

    with Connection(AMQP_URL) as conn:
        consumer = FanoutConsumer(conn)
        consumer.run()

    SEND_PARAMS = {
        'username': config_script['SMS']['username'],
        'password': config_script['SMS']['password'],
        'from': '8831',
    }
    SMSender(config_sms['alerta-mailer']['sms_url'],
             {**SEND_PARAMS, 'to': n, 'text': 'test 1'})
