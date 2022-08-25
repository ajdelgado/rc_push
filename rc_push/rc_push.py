#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
#
# This script is licensed under GNU GPL version 2.0 or above
# (c) 2022 Antonio J. Delgado
# __description__

import sys
import os
import logging
import click
import click_config_file
from logging.handlers import SysLogHandler
import requests
from rocketchat_API.rocketchat import RocketChat
import time
import stat
import json
class rc_push:

    def __init__(self, debug_level, log_file, user, password, use_auth_token, rc_url, ntfy_url, ntfy_topic, ntfy_user, ntfy_pass, channels):
        ''' Initial function called when object is created '''
        self.config = dict()
        self.config['debug_level'] = debug_level
        self.config['user'] = user
        self.config['channels'] = channels
        self.config['ntfy_url'] = ntfy_url
        self.config['ntfy_topic'] = ntfy_topic
        self.config['ntfy_user'] = ntfy_user
        self.config['ntfy_pass'] = ntfy_pass

        if log_file is None:
            log_file = os.path.join(os.environ.get('HOME', os.environ.get('USERPROFILE', os.getcwd())), 'log', 'rc_push.log')
        self.config['log_file'] = log_file
        self._init_log()

        self.session = requests.Session()
        self.wait = 30
        self._log.debug(f"Connecting to '{rc_url}' as the user '{user}'...")
        if use_auth_token:
            try:
                self.rc = RocketChat(
                    user_id=user,
                    auth_token=password,
                    server_url=rc_url,
                    session=self.session
                )
            #except rocketchat_API.APIExceptions.RocketExceptions.RocketAuthenticationException as error:
            except Exception as error:
                self._log.error(f"Error connecting to Rocket Chat server '{rc_url}' with user id '{user}'. {error}")
                exit(1)
        else:
            try:
                self.rc = RocketChat(
                    user,
                    password,
                    server_url=rc_url,
                    session=self.session
                )
            #except rocketchat_API.APIExceptions.RocketExceptions.RocketAuthenticationException as error:
            except Exception as error:
                self._log.error(f"Error connecting to Rocket Chat server '{rc_url}' as user '{user}'. {error}")
                exit(1)
        self.notifications = {}

        while True:
            print("Checking unread private messages...")
            self.check_new_private_messages()
            print(f"Waiting {self.wait} seconds...")
            time.sleep(self.wait)
            
            print("Checking groups...")
            self.check_new_group_messages()
            print(f"Waiting {self.wait} seconds...")
            time.sleep(self.wait)
            
            print("Checking unread channels...")
            self.check_new_channel_messages()
            print(f"Waiting {self.wait} seconds...")
            time.sleep(self.wait)

    def send_message_to_user(self, user, message):
        rooms = self.rc.rooms_get().json()['update']
        for room in rooms:
            if len(room['usernaes']) == 2 and user in room['usernames'] and config['user'] in room['usernames']:
                our_room = room
        message = {
            "rid": our_room['_id'],
            "msg": message
        }
        return rc.chat_send_message(message)

    def check_new_private_messages(self):
        ims = self.rc.im_list()
        if 'ims' not in ims.json():
            self._log.error(f"Not found list of 'ims': {ims.json()}")
            return False
        for im in ims.json()['ims']:
            #print(json.dumps(im, indent=2))
            room_counters = self.rc.im_counters(room_id=im['_id'])
            #print(room_counters)
            if 'unreads' not in room_counters.json():
                # print(room_counters.headers)
                # print(room_counters.json())
                ratelimit_reset = room_counters.headers['X-RateLimit-Reset']
                wait = int((int(ratelimit_reset)/1000) - time.time()) + 1
                self._log.warning(f"Rate-limit exceded, waiting {wait} seconds")
                time.sleep(wait)
                # print(room_counters.headers)
                # print(room_counters.json())
                room_counters = self.rc.channels_counters(room_id=im['_id'])
                if 'unreads' not in room_counters.json():
                    return False
            else:
                self.wait = 1
            unreads = room_counters.json()['unreads']
            if unreads and int(unreads) > 0:
                if im['_id'] not in self.notifications or self.notifications[im['_id']] != unreads:
                    # print(json.dumps(im, indent=2))
                    self.notifications[im['_id']] = unreads
                    self.ntfy_send(message=f"You have {unreads} unread message(s) from '{im['lastMessage']['u']['name']}': '{im['lastMessage']['md'][0]['value'][0]['value']}'")
            if int(room_counters.headers['X-RateLimit-Remaining']) < 5:
                time.sleep(self.wait * 2)
            # else:
            #     print(f"{int(room_counters.headers['X-RateLimit-Remaining'])} requests remaining...")

    def check_new_group_messages(self):
        groups = self.rc.groups_list().json()
        #print(json.dumps(groups, indent=2))
        for group in groups['groups']:
            if ('channels' in self.config
            and len(self.config['channels']) > 0
            and group['name'] not in self.config['channels']):
                self._log.debug(f"Skipping non-listed group '{group['name']}'.")
                continue
            #print(json.dumps(group, indent=2))
            room_counters = self.rc.call_api_get("groups.counters", roomId=group['_id'])
            #print(room_counters)
            if 'unreads' not in room_counters.json():
                ratelimit_reset = room_counters.headers['X-RateLimit-Reset']
                wait = int((int(ratelimit_reset)/1000) - time.time()) + 1
                self._log.warning(f"Rate-limit exceded, waiting {wait} seconds")
                time.sleep(wait)
                # print(room_counters.headers)
                # print(room_counters.json())
                room_counters = self.rc.call_api_get("groups.counters", roomId=group['_id'])
                if 'unreads' not in room_counters.json():
                    return False
            else:
                self.wait = 1
            unreads = room_counters.json()['unreads']
            if unreads and int(unreads) > 0:
                if group['_id'] not in self.notifications or self.notifications[group['_id']] != unreads:
                    # print(json.dumps(channel, indent=2))
                    self.notifications[group['_id']] = unreads
                    self.ntfy_send(message=f"You have {unreads} unread message(s) in '{group['name']}' from '{group['lastMessage']['u']['name']}': '{group['lastMessage']['md'][0]['value'][0]['value']}'")
                else:
                    self._log.debug(f"No changes in unread {unreads}")
            else:
                self._log.debug("No unread messages")
            if int(room_counters.headers['X-RateLimit-Remaining']) < 5:
                time.sleep(self.wait * 2)
            # else:
            #     print(f"{int(room_counters.headers['X-RateLimit-Remaining'])} requests remaining...")

    def check_new_channel_messages(self):
        for channel in self.rc.channels_list().json()['channels']:
            if ('channels' in self.config
            and len(self.config['channels']) > 0
            and channel['name'] not in self.config['channels']):
                self._log.debug(f"Skipping non-listed channel '{channel['name']}'.")
                continue
            #print(json.dumps(channel, indent=2))
            room_counters = self.rc.channels_counters(room_id=channel['_id'])
            #print(room_counters)
            if 'unreads' not in room_counters.json():
                ratelimit_reset = room_counters.headers['X-RateLimit-Reset']
                wait = int((int(ratelimit_reset)/1000) - time.time()) + 1
                self._log.warning(f"Rate-limit exceded, waiting {wait} seconds")
                time.sleep(wait)
                # print(room_counters.headers)
                # print(room_counters.json())
                room_counters = self.rc.channels_counters(room_id=channel['_id'])
                if 'unreads' not in room_counters.json():
                    return False
            else:
                self.wait = 1
            unreads = room_counters.json()['unreads']
            if unreads and int(unreads) > 0:
                if channel['_id'] not in self.notifications or self.notifications[channel['_id']] != unreads:
                    # print(json.dumps(channel, indent=2))
                    self.notifications[channel['_id']] = unreads
                    self.ntfy_send(message=f"You have {unreads} unread message(s) in '{channel['name']}' from '{channel['lastMessage']['u']['name']}': '{channel['lastMessage']['md'][0]['value'][0]['value']}'")
                else:
                    self._log.debug(f"No changes in unread {unreads}")
            else:
                self._log.debug("No unread messages")
            if int(room_counters.headers['X-RateLimit-Remaining']) < 5:
                time.sleep(self.wait * 2)
            # else:
            #     print(f"{int(room_counters.headers['X-RateLimit-Remaining'])} requests remaining...")


    def ntfy_send(self, message):
        url = f"{self.config['ntfy_url']}/{self.config['ntfy_topic']}"
        result = self.session.post(
            url,
            data=message.encode(encoding='utf-8'),
            auth=requests.auth.HTTPBasicAuth(self.config['ntfy_user'], self.config['ntfy_pass'])
        )
        if result.status_code > 299:
            self._log.error(f"Error {result.status_code} publishing in ntfy.")
            self._log.error(result.json())

    def _init_log(self):
        ''' Initialize log object '''
        self._log = logging.getLogger("rc_push")
        self._log.setLevel(logging.DEBUG)

        sysloghandler = SysLogHandler()
        sysloghandler.setLevel(logging.DEBUG)
        self._log.addHandler(sysloghandler)

        streamhandler = logging.StreamHandler(sys.stdout)
        streamhandler.setLevel(logging.getLevelName(self.config.get("debug_level", 'INFO')))
        self._log.addHandler(streamhandler)

        if 'log_file' in self.config:
            log_file = self.config['log_file']
        else:
            home_folder = os.environ.get('HOME', os.environ.get('USERPROFILE', ''))
            log_folder = os.path.join(home_folder, "log")
            log_file = os.path.join(log_folder, "rc_push.log")

        if not os.path.exists(os.path.dirname(log_file)):
            os.mkdir(os.path.dirname(log_file))

        filehandler = logging.handlers.RotatingFileHandler(log_file, maxBytes=102400000)
        # create formatter
        formatter = logging.Formatter('%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
        filehandler.setFormatter(formatter)
        filehandler.setLevel(logging.DEBUG)
        self._log.addHandler(filehandler)
        return True

@click.command()
@click.option("--debug-level", "-d", default="INFO",
    type=click.Choice(
        ["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"],
        case_sensitive=False,
    ), help='Set the debug level for the standard output.')
@click.option('--log-file', '-l', help="File to store all debug messages.")
@click.option('--user', '-u', required=True, help='Rocket.Chat user name')
@click.option('--password', '-p', required=True, help='Rocket.Chat user password')
@click.option('--use-auth-token', '-a', default=False, help='If true, would consider user the user_id and password the authentication token to use to connecto to RicketChat')
@click.option('--rc-url', '-r', required=True, help='Rocket.Chat URL')
@click.option('--ntfy-url', '-n', required=True, help='URL of your ntfy instance')
@click.option('--ntfy-topic', '-t', required=True, help='Topic in ntfy')
@click.option('--ntfy-user', '-U', required=True, help='User name in ntfy')
@click.option('--ntfy-pass', '-P', required=True, help='User password in ntfy')
@click.option('--channels', '-c', multiple=True, help='Channel to check for messages. If omited all channels will be check, and might take long.')
@click_config_file.configuration_option()
def __main__(debug_level, log_file, user, password, use_auth_token, rc_url, ntfy_url, ntfy_topic,
             ntfy_user, ntfy_pass, channels):
    object = rc_push(debug_level, log_file, user, password, use_auth_token, rc_url, ntfy_url, ntfy_topic,
                     ntfy_user, ntfy_pass, channels)
    object._log.info('Initialized rc_push')

if __name__ == "__main__":
    __main__()

