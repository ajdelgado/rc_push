#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
#
# This script is licensed under GNU GPL version 2.0 or above
# (c) 2022 Antonio J. Delgado
# __description__

import sys
import os
import logging
import time
import json
from logging.handlers import SysLogHandler
import click
import click_config_file
import requests
from rocketchat_API.rocketchat import RocketChat
import redis


class rc_push:
    '''Push RocketChat message notifications to ntfy'''

    def __init__(self, **kwargs):
        ''' Initial function called when object is created '''
        self.config = kwargs

        if self.config['log_file'] is None:
            log_file = os.path.join(os.environ.get(
                'HOME',
                os.environ.get('USERPROFILE', os.getcwd())),
                'log',
                'rc_push.log'
            )
            self.config['log_file'] = log_file
        self._init_log()

        self.redis = redis.from_url(self.config['redis_url'])
        if not self.redis.ping():
            self._log.error("Error connecting to Redis server: %s", self.config['redis_url'])
            sys.exit(1)

        self.session = requests.Session()
        self.wait = self.config['wait']
        self._log.debug(
            "Connecting to '%s' as the user '%s'...", self.config['rc_url'], self.config['user'])
        if self.config['use_auth_token']:
            try:
                self.rc = RocketChat(
                    user_id=self.config['user'],
                    auth_token=self.config['password'],
                    server_url=self.config['rc_url'],
                    session=self.session
                )
            # except rocketchat_API.APIExceptions.RocketExceptions
            # .RocketAuthenticationException as error:
            except Exception as error:
                self._log.error("Error connecting to Rocket Chat server '%s' with user id '%s'. %s", self.config['rc_url'], self.config['user'], error)
                sys.exit(1)
        else:
            try:
                self.rc = RocketChat(
                    self.config['user'],
                    self.config['password'],
                    server_url=self.config['rc_url'],
                    session=self.session
                )
            # except rocketchat_API.APIExceptions.RocketExceptions
            # .RocketAuthenticationException as error:
            except Exception as error:
                self._log.error("Error connecting to Rocket Chat server '%s' as user '%s'. %s", self.config['rc_url'], self.config['user'], error)
                sys.exit(1)
        self.notifications = {}

        while True:
            print("Checking unread private messages...")
            self.check_new_private_messages()
            print(f"Waiting {self.wait} seconds...")
            time.sleep(self.wait)

            if self.config['check_groups']:
                print("Checking groups...")
                self.check_new_group_messages()
                print(f"Waiting {self.wait} seconds...")
                time.sleep(self.wait)

            if self.config['check_channels']:
                print("Checking unread channels...")
                self.check_new_channel_messages()
                print(f"Waiting {self.wait} seconds...")
                time.sleep(self.wait)

    def send_message_to_user(self, user, message):
        rooms = self.rc.rooms_get().json()['update']
        for room in rooms:
            if (len(room['usernaes']) == 2 and
               user in room['usernames'] and
               self.config['user'] in room['usernames']):
                our_room = room
        message = {
            "rid": our_room['_id'],
            "msg": message
        }
        return self.rc.chat_send_message(message)

    def _join_names(self, items):
        if len(items) == 1:
            return items[0]
        count=0
        for item in items:
            count +=1
            if count > 1:
                if count > len(items)-1:
                    result = f"{result} and {item}"
                else:
                    result = f"{result}, {item}"
            else:
                result = item
        return result

    def check_new_private_messages(self):
        '''Check for new private messages'''
        ims = self.rc.im_list()
        self._log.info("Checking %s private rooms...", len(ims.json()))
        if 'ims' not in ims.json():
            self._log.error("Not found list of 'ims': %s", ims.json())
            return False
        for im in ims.json()['ims']:
            # self._log.debug("Private message room: %s", json.dumps(im, indent=2))
            users = self._join_names(im['usernames'])
            self._log.debug(
                'Private message room between %s has %s messages',
                users,
                im['msgs']
            )
            if im['msgs'] > 0 and 'lastMessage' in im:
                room_counters = self.rc.im_counters(room_id=im['_id'])
                # print(room_counters)
                if 'unreads' not in room_counters.json():
                    self._log.debug("Counters headers: %s", room_counters.headers)
                    self._log.debug("Counters result: %s", room_counters.json())
                    ratelimit_reset = room_counters.headers.get(
                        'X-RateLimit-Reset', 0
                    )
                    wait = int((int(ratelimit_reset)/1000) - time.time()) + 2
                    self._log.warning("Rate-limit exceded, waiting %s seconds", wait)
                    time.sleep(wait)
                    room_counters = self.rc.im_counters(room_id=im['_id'])
                    self._log.debug("Counters headers: %s", room_counters.headers)
                    self._log.debug("Counters result: %s", room_counters.json())
                    if 'unreads' not in room_counters.json():
                        return False
                else:
                    self.wait = self.config['wait']
                unreads = room_counters.json().get('unreads', 0)
                self._log.debug(
                    "There are %s unread private messages in chat %s between users %s.",
                    unreads,
                    im['_id'],
                    users
                )
                if unreads and int(unreads) > 0:
                    if (im['_id'] not in self.notifications or
                       self.notifications[im['_id']] != unreads):
                        # print(json.dumps(im, indent=2))
                        self.notifications[im['_id']] = unreads
                        self.ntfy_send(
                            message=f"""You have {unreads} unread private
message(s) from '{im['lastMessage']['u']['name']}':
'{im['lastMessage']['md'][0]['value'][0]['value']}'"""
                        )
                if int(room_counters.headers['X-RateLimit-Remaining']) < 5:
                    time.sleep(self.wait * 2)
                # else:
                #     print(f"{int(room_counters.headers['X-RateLimit
                # -Remaining'])} requests remaining...")
            else:
                self._log.debug("There are no messages in chat %s between users %s", im['_id'], users)

    def check_new_group_messages(self):
        '''Check for new group messages'''
        groups = self.rc.groups_list().json()
        self._log.info(f"Checking {len(groups)} groups...")
        for group in groups['groups']:
            self._log.debug(f"Group: {json.dumps(groups, indent=2)}")
            if ('channels' in self.config
               and len(self.config['channels']) > 0
               and group['name'] not in self.config['channels']):
                self._log.info(f"Skipping non-listed group '{group['name']}'.")
                continue
            # print(json.dumps(group, indent=2))
            room_counters = self.rc.call_api_get(
                "groups.counters",
                roomId=group['_id']
            )
            # print(room_counters)
            if 'unreads' not in room_counters.json():
                self._log.debug(room_counters.headers)
                self._log.debug(room_counters.json())
                ratelimit_reset = room_counters.headers.get(
                    'X-RateLimit-Reset',
                    0
                )
                wait = int((int(ratelimit_reset)/1000) - time.time()) + 1
                self._log.warning(
                    f"Rate-limit exceded, waiting {wait} seconds"
                )
                time.sleep(wait)
                # print(room_counters.headers)
                # print(room_counters.json())
                room_counters = self.rc.call_api_get(
                    "groups.counters",
                    roomId=group['_id']
                )
                if 'unreads' not in room_counters.json():
                    return False
            else:
                self.wait = self.config['wait']
            unreads = room_counters.json()['unreads']
            if unreads and int(unreads) > 0:
                if (group['_id'] not in self.notifications or
                   self.notifications[group['_id']] != unreads):
                    print(json.dumps(group, indent=2))
                    self.notifications[group['_id']] = unreads
                    if 'lastMessage' in group:
                        sender = group['lastMessage']['u']['name']
                        if self.config['private']:
                            message = '(message content is private)'
                        else:
                            message = group['lastMessage']['md'][0]['value'][0]['value']
                        self.ntfy_send(
                            message=f"""You have {unreads} unread message(s)
in '{group['name']}' from '{sender}': {message}"""
                        )
                    else:
                        self.ntfy_send(
                            message=f"""You have {unreads} unread message(s)
in '{group['name']}'"""
                        )
                else:
                    self._log.debug(f"No changes in unread {unreads}")
            else:
                self._log.debug("No unread messages")
            if int(room_counters.headers['X-RateLimit-Remaining']) < 5:
                time.sleep(self.wait * 2)
            # else:
            #     print(f"{int(room_counters.headers['X-RateLimit
            # -Remaining'])} requests remaining...")

    def check_new_channel_messages(self):
        channels = self.rc.channels_list().json()['channels']
        self._log.info(f"Checking {len(channels)} channels...")
        for channel in channels:
            self._log.debug(f"Channel: {json.dumps(channel, indent=2)}")
            if ('channels' in self.config
               and len(self.config['channels']) > 0
               and channel['name'] not in self.config['channels']):
                self._log.debug(
                    f"Skipping non-listed channel '{channel['name']}'."
                )
                continue
            # print(json.dumps(channel, indent=2))
            room_counters = self.rc.channels_counters(room_id=channel['_id'])
            # print(room_counters)
            if 'unreads' not in room_counters.json():
                self._log.debug(room_counters.headers)
                self._log.debug(room_counters.json())
                ratelimit_reset = room_counters.headers.get(
                    'X-RateLimit-Reset', 0
                )
                wait = int((int(ratelimit_reset)/1000) - time.time()) + 1
                self._log.warning(
                    f"Rate-limit exceded, waiting {wait} seconds"
                )
                time.sleep(wait)
                # print(room_counters.headers)
                # print(room_counters.json())
                room_counters = self.rc.channels_counters(
                    room_id=channel['_id']
                )
                if 'unreads' not in room_counters.json():
                    return False
            else:
                self.wait = self.config['wait']
            unreads = room_counters.json()['unreads']
            if unreads and int(unreads) > 0:
                if (channel['_id'] not in self.notifications or
                   self.notifications[channel['_id']] != unreads):
                    # print(json.dumps(channel, indent=2))
                    self.notifications[channel['_id']] = unreads
                    if 'lastMessage' in channel:
                        if self.config['private']:
                            message = '(message content is private)'
                        else:
                            message = channel['lastMessage']['md'][0]['value'][0]['value']
                        self.ntfy_send(
                            message=f"""You have {unreads} unread message(s)
in '{channel['name']}' from '{channel['lastMessage']['u']['name']}':
'{message}'"""
                        )
                    else:
                        self.ntfy_send(
                            message=f"""You have {unreads} unread message(s)
in '{channel['name']}'"""
                        )
                else:
                    self._log.debug(f"No changes in unread {unreads}")
            else:
                self._log.debug("No unread messages")
            if int(room_counters.headers['X-RateLimit-Remaining']) < 5:
                time.sleep(self.wait * 2)
            # else:
            #     print(f"{int(room_counters.headers['X-RateLimit
            # -Remaining'])} requests remaining...")

    def ntfy_send(self, message):
        if not self.redis.get(f"rc_push_ntfy_{message}") == "1":
            url = f"{self.config['ntfy_url']}/{self.config['ntfy_topic']}"
            self._log.info(f"Posting to ntfy message '{message}'...")
            result = self.session.post(
                url,
                data=message.encode(encoding='utf-8'),
                auth=requests.auth.HTTPBasicAuth(
                    self.config['ntfy_user'],
                    self.config['ntfy_pass']
                )
            )
            if result.status_code > 299:
                self._log.error(
                    f"Error {result.status_code} publishing in ntfy."
                )
                self._log.error(result.json())
            self.redis.set(f"rc_push_ntfy_{message}", "1")
        else:
            self._log.debug(f"Not sending again message '{message}'")

    def _init_log(self):
        ''' Initialize log object '''
        self._log = logging.getLogger("rc_push")
        self._log.setLevel(logging.DEBUG)

        sysloghandler = SysLogHandler()
        sysloghandler.setLevel(logging.DEBUG)
        self._log.addHandler(sysloghandler)

        streamhandler = logging.StreamHandler(sys.stdout)
        streamhandler.setLevel(
            logging.getLevelName(self.config.get("debug_level", 'INFO'))
        )
        self._log.addHandler(streamhandler)

        if 'log_file' in self.config:
            log_file = self.config['log_file']
        else:
            home_folder = os.environ.get(
                'HOME', os.environ.get('USERPROFILE', '')
            )
            log_folder = os.path.join(home_folder, "log")
            log_file = os.path.join(log_folder, "rc_push.log")

        if not os.path.exists(os.path.dirname(log_file)):
            os.mkdir(os.path.dirname(log_file))

        filehandler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=102400000
        )
        # create formatter
        formatter = logging.Formatter(
            '%(asctime)s %(name)-12s %(levelname)-8s %(message)s'
        )
        filehandler.setFormatter(formatter)
        filehandler.setLevel(logging.DEBUG)
        self._log.addHandler(filehandler)
        return True


@click.command()
@click.option(
    "--debug-level",
    "-d",
    default="INFO",
    type=click.Choice(
        ["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"],
        case_sensitive=False,
    ),
    help='Set the debug level for the standard output.'
)
@click.option('--log-file', '-l', help="File to store all debug messages.")
@click.option('--user', '-u', required=True, help='Rocket.Chat user name')
@click.option(
    '--password',
    '-p',
    required=True,
    help='Rocket.Chat user password'
)
@click.option(
    '--use-auth-token',
    '-a',
    default=False,
    help='''If true, would consider user the user_id and password the
authentication token to use to connecto to RicketChat'''
)
@click.option('--rc-url', '-r', required=True, help='Rocket.Chat URL')
@click.option(
    '--ntfy-url',
    '-n',
    required=True,
    help='URL of your ntfy instance'
)
@click.option('--ntfy-topic', '-t', required=True, help='Topic in ntfy')
@click.option('--ntfy-user', '-U', required=True, help='User name in ntfy')
@click.option('--ntfy-pass', '-P', required=True, help='User password in ntfy')
@click.option(
    '--channels',
    '-c',
    multiple=True,
    help='''Channel to check for messages. If omited all channels will be
check, and might take long.'''
)
@click.option(
    '--redis-url',
    '-R',
    default='unix:///var/run/redis/redis-server.sock?decode_responses=True\
&health_check_interval=2',
    help='''URL to connect to redis server. Check documentation for
from_url at
https://github.com/redis/redis-py/blob/master/docs/examples/connection_\
examples.ipynb'''
)
@click.option(
    '--check-groups',
    '-g',
    default=True,
    help='Check new messages in groups'
)
@click.option(
    '--check-channels',
    '-C',
    default=True,
    help='Check new messages in channels'
)
@click.option(
    '--private',
    '-p',
    default=True,
    help='Messages should be kept private and not sent to ntfy service.'
)
@click.option('--wait', '-w', default=1, help='Seconds to wait between queries')
@click_config_file.configuration_option()
def __main__(**kwargs):
    return rc_push(**kwargs)


if __name__ == "__main__":
    __main__()
