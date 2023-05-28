#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Small script to serve the SpaceAPI JSON API."""

import argparse
import hmac
import os
import sys
import requests
from datetime import datetime, timedelta
from time import sleep

from dateutil.tz import tzlocal
from flask import Flask, abort, jsonify, redirect, request, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import OperationalError

from lib_doorstate import (DoorState, add_debug_arg, add_host_arg, add_key_arg,
                           add_port_arg, add_sql_arg, calculate_hmac,
                           human_time_since, parse_args_and_read_key,
                           to_timestamp)

WEBSITE_URL = 'https://temporaerhaus.de'  # without trailing slash
ADDRESS = 'Augsburger Str. 23-25, 89231 Neu-Ulm, Germany'
LAT = 48.3962895 
LON = 10.0019903
# PHONE = '+49 9131 85 28013'


def parse_args():
    """Return parsed command line arguments."""
    parser = argparse.ArgumentParser(__doc__)

    add_debug_arg(parser)
    add_key_arg(parser)
    add_host_arg(parser)
    add_port_arg(parser)
    add_sql_arg(parser)

    return parse_args_and_read_key(parser)


ARGS = parse_args()
APP = Flask(
    __name__,
    static_folder='../static/',
    static_url_path='/spaceapi/static'
)
APP.config['SQL'] = ARGS.sql
APP.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# if environment variable SPACEAPI_$CONFIG is set, this value will be used
for key, value in os.environ.items():
    if key.startswith('SPACEAPI_'):
        APP.config[key.replace('SPACEAPI_', '', 1)] = value

if os.path.isfile('/etc/spaceapi.py'):
    APP.config.from_pyfile('/etc/spaceapi.py')

APP.config['SQLALCHEMY_DATABASE_URI'] = APP.config['SQL']
DB = SQLAlchemy(APP)


class Event(DB.Model):
    """A timestamp annotated event."""

    __tablename__ = 'events'
    name = DB.Column(
        DB.String(length=12),
        primary_key=True,
    )
    timestamp = DB.Column(
        DB.DateTime(),
        nullable=True,
        default=datetime.utcnow,
    )

    def __repr__(self):
        return '{}({}, {})'.format(
            self.__class__.__name__,
            repr(self.name),
            repr(self.timestamp),
        )

    @classmethod
    def get_last_update(cls):
        """Return that entry with name 'last_update' or create a new one."""
        last_update = cls.query.get('last_update')
        if not last_update:
            last_update = Event(
                name='last_update',
                timestamp=datetime.fromtimestamp(0),
            )
            DB.session.add(last_update)
            DB.session.commit()
        return last_update

    @classmethod
    def last_update_is_outdated(cls):
        """
        Return True if the timestamp of the entry with name 'last_update' is older than 10 minutes.
        """
        evt = cls.get_last_update()
        return (datetime.now() - evt.timestamp) > timedelta(minutes=10)

    @classmethod
    def touch_last_update(cls):
        """Set the timestamp of 'last_update' event to now."""
        evt = cls.get_last_update()
        evt.timestamp = datetime.now()
        DB.session.commit()

class OpeningPeriod(DB.Model):
    """An entry for a time duration when the door was opened."""

    __tablename__ = 'openingperiod'
    opened = DB.Column(
        DB.DateTime(timezone=True),
        primary_key=True,
        index=True,
        default=datetime.utcnow,
    )
    closed = DB.Column(
        DB.DateTime(timezone=True),
        nullable=True,
    )
    message = DB.Column(
        DB.String(length=255),
        nullable=True,
    )


    def __init__(self, opened, closed=None, message=None):
        self.opened = opened
        self.closed = closed
        self.message = message

    def __repr__(self):
        return '{}({}, {}, {})'.format(
            self.__class__.__name__,
            repr(self.opened),
            repr(self.closed),
            repr(self.message),
        )

    @property
    def opened_timestamp(self):
        """Return the integer timestamp for the opened time of this entry."""
        return to_timestamp(self.opened)

    @property
    def closed_timestamp(self):
        """Return the integer timestamp for the closed time of this entry."""
        return to_timestamp(self.closed) if self.closed else None

    @property
    def is_open(self):
        """Return True if this entry has no closed entry."""
        return self.closed is None

    @property
    def state(self):
        """Return DoorState.opened if self.is_open else DoorState.closed."""
        return DoorState.opened if self.is_open else DoorState.closed

    @property
    def last_change_timestamp(self):
        """Return the timestamp of the last change of this entry."""
        return to_timestamp(self.opened if self.is_open else self.closed)

    def to_dict(self):
        """Return a json serializable dict for this entry."""
        return {
            'opened': self.opened_timestamp,
            'closed': self.closed_timestamp,
            'message': self.message,
        }

    @classmethod
    def get_latest_state(cls):
        """Return the most up to date entry."""
        return OpeningPeriod.query.order_by(DB.desc(cls.opened)).first()


@APP.route('/')
def root():
    """Redirect to /."""
    return redirect(url_for('spaceapi'), 301)

@APP.route('/spaceapi/')
def old_dir():
    """Redirect to /."""
    return redirect(url_for('spaceapi'), 301)


@APP.route('/spaceapi.json')
def spaceapi():
    """
    Return the SpaceAPI JSON (spaceapi.net).

    This one is valid for version 0.8, 0.9, 0.11, 0.13.
    feeds as dictionary breaks compatibility to 0.12.
    """
    latest_door_state = OpeningPeriod.get_latest_state()
    outdated = Event.last_update_is_outdated() or not latest_door_state
    is_open = not outdated and latest_door_state.is_open
    state_last_change = int(Event.get_last_update().timestamp.timestamp())
    state_message = 'doorstate is outdated' if outdated else (
        latest_door_state.message or ('door is open' if is_open else 'door is closed')
    )

    return jsonify({
        'api': '0.13',
        'space': 'temporärhaus',
        'logo': WEBSITE_URL + '/spaceicons/logo.svg',
        'url': WEBSITE_URL + '/',
        'address': ADDRESS,
        'lat': LAT,
        'lon': LON,
        'open': is_open,
        'status': state_message,
        'lastchange': state_last_change,
        # 'phone': PHONE,
        'location': {
            'address': ADDRESS,
            'lat': LAT,
            'lon': LON,
        },
        #'spacefed': {
        #    'spacenet': False,
        #    'spacesaml': False,
        #    'spacephone': False,
        #},
        'state': {
            'lastchange': state_last_change,
            'open': is_open,
            'message': state_message,
            'icon': {
                'open': WEBSITE_URL + '/spaceicons/tph-open.svg',
                'closed': WEBSITE_URL + '/spaceicons/tph-closed.svg',
            },
        },
        'cache': {
            'schedule': "m.05",
        },
        'projects': [
        #    WEBSITE_URL + '/project/',
            "https://github.com/temporaerhaus/",
        ],
        'issue_report_channels': [
            "twitter",
            "email",
        ],
        'contact': {
            #'phone': PHONE,
            #'sip': 'sip:3280@hg.eventphone.de',
            'twitter': "@temporaerhaus",
            'mastodon': "@temporaerhaus@chaos.social",
            #'ml': "fablab-aktive@fablab.fau.de",
            #'facebook': "https://facebook.com/FAUFabLab",
            #'google': {
            #    'plus': "+FAUFabLabErlangen",
            #},
            #'issue_mail': 'c3BhY2VhcGlAZmFibGFiLmZhdS5kZQ==',  # base64 encoded
            'email': "kontakt@temporaerhaus.de"
        },
        'feeds': {
            'blog': {
                'type': 'rss',
                'url': WEBSITE_URL + '/feed/',
            },
            'calendar': {
                'type': 'ical',
                'url': 'https://calendar.google.com/calendar/ical/slaun4l80uh2s0ototiol4qkgo%40group.calendar.google.com/public/basic.ics'
            }
        },
        'icon': {
            'open': WEBSITE_URL + '/spaceicons/tph-open.svg',
            'closed': WEBSITE_URL + '/spaceicons/tph-closed.svg',
        }
    })


@APP.route('/door/', methods=('GET', ))
def get_doorstate():
    """Return the current door state."""
    latest_door_state = OpeningPeriod.get_latest_state()
    outdated = Event.last_update_is_outdated() or not latest_door_state
    if outdated:
        text = 'Keine aktuellen Informationen über den Türstatus vorhanden.'
    elif not latest_door_state.is_open and \
            latest_door_state.closed.date() != datetime.now(tzlocal()).date():
        text = 'Das TPH war heute noch nicht geöffnet.'
    elif not latest_door_state.is_open:
        text = 'Das TPH war zuletzt vor {} geöffnet.'.format(
            human_time_since(latest_door_state.closed)
        )
    elif latest_door_state.is_open:
        text = 'Das TPH ist seit {} offen.'.format(
            human_time_since(latest_door_state.opened)
        )
    return jsonify({
        'state': 'unknown' if outdated else latest_door_state.state.name,
        'time': latest_door_state.opened_timestamp if latest_door_state else 0,
        'text': text,
    })


@APP.route('/door/', methods=('POST', ))
def update_doorstate():
    """Update doorstate (opened, close, ...)."""
    required_params = {'time', 'state'}
    #required_params = {'time', 'state', 'hmac'}

    data = request.json or request.form

    # validate
    try:
        for param in required_params:
            if not data.get(param, None):
                raise ValueError(param, 'Parameter is missing')
        auth_header = request.headers.get('Authorization')
        if auth_header:
            auth_token = auth_header.split(" ")[1]
        else:
            auth_token = ''
        #if not hmac.compare_digest(
        #    calculate_hmac(data['time'], data['state'], ARGS.key),
        #    data['hmac']
        #):
        if auth_token != ARGS.key:
            raise ValueError('key', 'key is wrong. Do you have the right key?')
        if not str(data['time']).isnumeric():
            raise ValueError('time', 'Time has to be an integer timestamp.')
        time = datetime.fromtimestamp(int(data['time']), tzlocal())
        if abs(time - datetime.now(tzlocal())).total_seconds() > 60:
            raise ValueError('time', 'Time is too far in the future or past. Use NTP! (server time: %s)' % (datetime.now(tzlocal()).strftime("%s"),))
        time = datetime.now(tzlocal())
        # shortcut for member state
        if data['state'] == 'member':
            data['state'] = 'opened'
            data['message'] = 'member'
        if data['state'] not in DoorState.__members__:
            raise ValueError(
                'state',
                'State has to be one of {}.'.format(
                    ', '.join(DoorState.__members__.keys())
                )
            )
        state = DoorState[data['state']]
        message = data.get('message', None)
        latest_door_state = OpeningPeriod.get_latest_state()
        # update watchdog
        if 'WATCHDOG_URL' in APP.config:
            requests.get("%s?m=Door+now+%s" % (APP.config['WATCHDOG_URL'], state,))
        if latest_door_state:
            if latest_door_state.state == state and latest_door_state.message == message:
                # already opened/closed
                Event.touch_last_update()
                return jsonify({
                    'time': latest_door_state.last_change_timestamp,
                    'state': latest_door_state.state.name,
                    '_text': 'door was already {} at {}'.format(
                        latest_door_state.state.name, latest_door_state.last_change_timestamp,
                    ),
                })
            elif latest_door_state.state == state and state == DoorState.opened and latest_door_state.message != message:
                # already opened but with different message
                # close old entry
                latest_door_state.closed = time
                APP.logger.debug(
                    'Closing door. Resulting entry: open from %(opened)i till %(closed)i',
                    latest_door_state.to_dict()
                )
                DB.session.commit()
                # open new entry
                latest_door_state = OpeningPeriod(opened=time, message=message)
                APP.logger.debug(
                    'Re-Opening door. New entry: open from %(opened)i till t.b.a.',
                    latest_door_state.to_dict()
                )
                DB.session.add(latest_door_state)
                DB.session.commit()
                return jsonify({
                    'time': latest_door_state.last_change_timestamp,
                    'state': latest_door_state.state.name,
                    '_text': 'door is now {} (time: {}) but with different message'.format(
                        latest_door_state.state.name, latest_door_state.last_change_timestamp,
                    ),
                })
            elif latest_door_state.last_change_timestamp >= to_timestamp(time):
                raise ValueError('time', 'New entry must be newer than latest entry.')
        elif state == DoorState.closed:
            # no entry: we assume the door was closed before -> already closed
            return jsonify({
                'time': 0,
                'state': DoorState.closed.name,
                '_text': "door was already closed."
                " To be honest, we don't have any data yet but the first entry has to be 'opened'.",
            })
    except ValueError as err:
        #print(data, file=sys.stderr)
        #print(err, file=sys.stderr)
        abort(400, {err.args[0]: err.args[1]})

    # update doorstate
    if latest_door_state and latest_door_state.is_open and state == DoorState.closed:
        latest_door_state.closed = time
        APP.logger.debug(
            'Closing door. Resulting entry: open from %(opened)i till %(closed)i',
            latest_door_state.to_dict()
        )
    elif (not latest_door_state or not latest_door_state.is_open) and state == DoorState.opened:
        latest_door_state = OpeningPeriod(opened=time, message=message)
        APP.logger.debug(
            'Opening door. New entry: open from %(opened)i till t.b.a.',
            latest_door_state.to_dict()
        )
        DB.session.add(latest_door_state)
    else:
        abort(500, 'This should not happen')
    DB.session.commit()
    Event.touch_last_update()
    return jsonify({
        'time': latest_door_state.last_change_timestamp,
        'state': latest_door_state.state.name,
        '_text': 'door is now {} (time: {})'.format(
            latest_door_state.state.name, latest_door_state.last_change_timestamp,
        ),
    })


@APP.route('/door/all/', methods=('GET', ))
def get_doorstate_all():
    """Return the current door state. Filter by opened time using from and to."""
    try:
        time_from = datetime.fromtimestamp(int(
            request.args.get(
                'from',
                (datetime.now(tzlocal()) - timedelta(days=365)).timestamp(),
            )
        ), tzlocal())
        time_to = datetime.fromtimestamp(int(
            request.args.get(
                'to',
                datetime.now(tzlocal()).timestamp(),
            )
        ), tzlocal())
    except ValueError:
        abort(400, 'From and to have to be timestamps')

    all_entries = OpeningPeriod.query.order_by(
        DB.asc(OpeningPeriod.opened)
    ).filter(
        OpeningPeriod.opened >= time_from,
        OpeningPeriod.opened <= time_to,
    ).limit(2000).all()
    return jsonify([entry.to_dict() for entry in all_entries])


@APP.route('/door/icon/', methods=('GET', ))
def get_doorstate_icon():
    """Redirect to the icon that describes the current door state."""
    latest_door_state = OpeningPeriod.get_latest_state()
    outdated = Event.last_update_is_outdated() or not latest_door_state
    logo_name = 'logo.svg' if outdated else (
        'tph-{}.svg'.format(latest_door_state.state.name)
    )
    return redirect(WEBSITE_URL + '/spaceicons/' + logo_name)


@APP.errorhandler(400)
@APP.errorhandler(404)
@APP.errorhandler(405)
@APP.errorhandler(500)
def errorhandler(error):
    """JSON encode error messages."""
    return jsonify({
        'error_code': getattr(error, 'code', 500),
        'error_name': getattr(error, 'name', 'Internal Server Error'),
        'error_description': getattr(error, 'description', ''),
    }), getattr(error, 'code', 500)


if __name__ == '__main__':
    # try 10 times to connect to database then fail
    DB_CONNECTION_RETRIES = 20
    for retry in range(1, DB_CONNECTION_RETRIES + 1):
        try:
            DB.create_all()
            break
        except OperationalError as err:
            APP.logger.error(
                'Failed to connect to database: Try %i of %i', retry, DB_CONNECTION_RETRIES
            )
            if retry == DB_CONNECTION_RETRIES:
                raise err
            sleep(1)
    APP.run(host=ARGS.host, port=ARGS.port, debug=ARGS.debug)
