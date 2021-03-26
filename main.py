import json
import logging
import re
import sys
import urllib
from base64 import b64decode, b64encode
from datetime import datetime, timedelta
from hashlib import sha256
from logging.handlers import RotatingFileHandler

import click
import requests


def setup_logs(location, verbose):
    logger = logging.getLogger()
    if location == '-':
        handler = logging.StreamHandler()
    else:
        handler = RotatingFileHandler(location)
    logger.setLevel(logging.DEBUG if verbose else logging.ERROR)
    handler.setLevel(logging.DEBUG if verbose else logging.ERROR)
    logger.addHandler(handler)


# noinspection PyDefaultArgument
def print_json(success: bool, data: dict = dict()):
    click.echo(json.dumps({
        'ok': 1 if success else 0,
        **data
    }))


def parse_time_duration(st):
    dt = datetime.strptime(st.split('.')[0], '%H:%M:%S')
    return int(timedelta(hours=dt.hour, minutes=dt.minute, seconds=dt.second).total_seconds())


class Duplicati:
    def __init__(self):
        self.session = requests.session()
        self.server_url = None


    def login(self, server_url: str, password: str):
        self.server_url = server_url
        login_url = f'{server_url}/login.cgi'

        nonce_request = self.session.post(login_url, {'get-nonce': 1})
        logging.debug(f'Nonce request: {nonce_request.status_code}')
        nonce_request.encoding = 'utf-8-sig'
        nonce_json = nonce_request.json()
        nonce = nonce_json.get('Nonce', None)
        salt = nonce_json.get('Salt', None)
        if nonce is None or salt is None:
            logging.error('No nonce nor salt :(')
            self.on_error()
        logging.info(f'Got salt, nonce: {salt} {nonce}')
        logging.debug(nonce_request.cookies)

        encrypted_password = sha256(password.encode('utf-8') + b64decode(salt)).digest()
        encrypted_with_nonce = b64encode(sha256(b64decode(nonce) + encrypted_password).digest()).decode('ascii')
        login_request = self.session.post(login_url, {'password': encrypted_with_nonce})
        logging.debug(f'Login request: {login_request.status_code}')

        if login_request.status_code == 200:
            logging.info('Login successful')
        else:
            logging.error('Login failed')
            logging.info(login_request.text)
            logging.info(login_request.headers)
            logging.info(login_request.cookies)
            self.on_error()


    def get_xsrf(self):
        return urllib.parse.unquote(self.session.cookies.get('xsrf-token'))


    def on_error(self):
        print_json(False)
        sys.exit(1)


    def get_backups(self):
        backups_url = f'{self.server_url}/api/v1/backups'
        backup_request = self.session.get(backups_url, headers={'X-XSRF-Token': self.get_xsrf()})
        if backup_request.status_code != 200:
            logging.error(f'Get backups failed: {backup_request.status_code}')
            logging.debug(backup_request.text)
            self.on_error()
        backup_request.encoding = 'utf-8-sig'
        return [job['Backup'] for job in backup_request.json()]


    def status(self):
        response = [
            {
                'id': int(backup['ID']),
                'name': backup['Name'],
                'size': int(backup['Metadata']['SourceFilesSize']),
                'time_started': int(datetime.strptime(backup['Metadata']['LastBackupStarted'], '%Y%m%dT%H%M%SZ').timestamp()),
                'time_finished': int(datetime.strptime(backup['Metadata']['LastBackupFinished'], '%Y%m%dT%H%M%SZ').timestamp()),
                'duration': parse_time_duration(backup['Metadata']['LastBackupDuration']),
                'count': int(backup['Metadata']['BackupListCount']),
            }
            for backup in self.get_backups()
        ]
        print_json(True, {'backups': response})


@click.group()
@click.option('--server-url', required=True, help='Example: http://some.server.com:1234')
@click.option('--password', required=True)
@click.option('--log-file', default='-')
@click.option('--verbose', is_flag=True, default=False)
@click.pass_context
def cli(context, server_url, password, log_file, verbose):
    setup_logs(log_file, verbose)

    server_url = re.sub('/$', '', server_url)

    duplicati = Duplicati()
    duplicati.login(server_url, password)
    context.obj = duplicati


@cli.command()
@click.pass_obj
def status(duplicati):
    duplicati.status()


if __name__ == '__main__':
    cli()
