#   Copyright 2014 Rackspace
#
#   Licensed under the Apache License, Version 2.0 (the "License"); you may
#   not use this file except in compliance with the License. You may obtain
#   a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#   License for the specific language governing permissions and limitations
#   under the License.
#

"""Command-line interface to Waldo."""

from __future__ import print_function

import argparse
import copy
import json
import logging
import sys
import os

from concurrent import futures
import keyring
import requests
from tabulate import tabulate

from waldoc import batch
from waldoc import client
from waldoc import consts

LOG = logging.getLogger(__name__)


def log_messages_to_stdout():
    """Attach a StreamHandler to the root logger."""
    logging.getLogger().setLevel(logging.DEBUG)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG)
    logging.getLogger().addHandler(ch)


def exit_error(message):
    print("ERROR: %s" % message)
    sys.exit(1)


def exit_http_exception(exception):
    print("Server Error:", exception)
    sys.exit(1)


def main():
    parser = setup_argparser()
    setup_subparsers(parser)
    args = parser.parse_args()
    if args.debug:
        log_messages_to_stdout()

    # attach the parser in case we need to throw
    # an 'ununusual' parser error after-the-fact
    # e.g. func._parser.error("You supplied forbidden args.")
    args.func._parser = parser
    args.func(args)

def setup_argparser():
    """Build and return parser object."""
    parser = argparse.ArgumentParser(
        description='Waldo client.')

    parser.add_argument('--server', dest='server',
                        default=os.environ.get('WALDO_SERVER',
                                               consts.PRODUCTION))

    # Token/username/password can be passed in 3 ways:
    #   Command-line, environment var, keyring
    parser.add_argument('--token', dest='token',
                        default=os.environ.get(
                            'WALDO_TOKEN',
                            keyring.get_password('waldoclient', 'token')),
                        help='Racker auth token')

    parser.add_argument('--username', dest='username',
                        default=os.environ.get(
                            'WALDO_USERNAME',
                            keyring.get_password('waldoclient', 'username')),
                        help='Racker SSO username. Securely store this '
                             'value in your keyring by running: '
                             '`keyring set waldoclient username`.')

    parser.add_argument('--password', dest='password',
                        default=os.environ.get(
                            'WALDO_PASSWORD',
                            keyring.get_password('waldoclient', 'password')),
                        help='Racker SSO password. Securely store this '
                             'value in your keyring by running: '
                             '`keyring set waldoclient password`.')

    verbose = parser.add_mutually_exclusive_group()
    verbose.add_argument('--debug', dest='debug', action='store_true',
                         default=False, help='output debug messages')
    verbose.add_argument('--quiet', dest='debug', action='store_true',
                         help='suppress output debug messages')
    return parser

def setup_subparsers(parser):
    """Attach subparsers."""

    subparsers = parser.add_subparsers(
        dest='_subparsers',
        title='subcommands',
        description='valid subcommands',
        help='additional help'
    )

    # `waldo list`
    list_parser = subparsers.add_parser('list', help='list help')
    # try nargs==argparse.REMAINDER
    list_parser.add_argument('targets', nargs='*',
                             help='Account Numbers, IP Addresses, or URLs.')
    list_parser.add_argument(
        '--tags', nargs='+', type=str, metavar='TAG',
        help="Filter by these tags.")
    list_parser.add_argument(
        '--page', type=int, default=0,
        help='Select page from paginated results')
    list_parser.set_defaults(func=list_discoveries)

    # `waldo show`
    show_parser = subparsers.add_parser('show', help='show help')
    show_parser.add_argument('discovery_id', help='Discovery UUID')
    show_parser.add_argument('--include-system-info',
                             dest='include_system_info',
                             action='store_true',
                             default=False,
                             help='Include raw system information')
    show_parser.set_defaults(func=show_discovery)

    # `waldo discover`
    discover_parser = subparsers.add_parser('discover', help='discover help')
    discover_parser.add_argument('account_or_netloc',
                                 help='Account ID or network location (URL)')
    discover_parser.add_argument('--dont-login',
                                 dest='dataplane',
                                 action='store_false',
                                 default=True,
                                 help='Do not login to servers')
    discover_parser.set_defaults(func=create_discovery)

    # `waldo version`
    version_parser = subparsers.add_parser('version', help='version help')
    version_parser.set_defaults(func=version)

    setup_batch_utility(subparsers)


def setup_batch_utility(subparsers):
    # `waldo batch`
    batch_parser = subparsers.add_parser(
        'batch',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        help=('Batch discovery commands. Used to execute discoveries '
              'in batches with common tags. Useful for grouping '
              'results for post-processing or running discoveries '
              'on many targets at once.'))
    batch_parser.add_argument(
        '--data', help=('Persistence file (json) which stores batch '
                        'discovery data and keeps track of batch discovery '
                        'jobs. Used as input targets file on subsequent '
                        'batch discovery runs.'),
        default=os.path.expanduser('~/.waldo_batch_discoveries.json'),
        type=lambda pth: os.path.realpath(os.path.expanduser(pth)),
        dest='persistence_file')
    batch_subparsers = batch_parser.add_subparsers(
        dest='_batch_subparsers', title='batch discovery commands',
        description='commands for managing batch discoveries')
    #
    # ` batch purge`
    #
    batch_purge_parser = batch_subparsers.add_parser(
        'purge',
        help="Drop/purge the persistence file w/ optional filters.")
    batch_purge_parser.add_argument(
        '--tags', nargs='+', type=str, metavar='TAG',
        help="Delete data with only these tags.")
    batch_purge_parser.add_argument(
        '--targets', nargs='+', metavar='account_or_netloc',
        help="Delete data for only these targets (Account Numbers, "
             "IP Addresses, or URLs).")
    batch_purge_parser.set_defaults(func=purge_persistence_file)

    #
    # ` batch discover`
    #
    batch_discover_parser = batch_subparsers.add_parser(
        'discover', help='Execute batch discovery jobs.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    targets_group = batch_discover_parser.add_mutually_exclusive_group()

    targets_group.add_argument(
        '--targets', nargs='+', metavar='account_or_netloc',
        help=('Batch discovery targets (Account Numbers, IP Addresses, '
              'or URLs).'))
    targets_group.add_argument(
        '--targets-file',
        help=('Targets file with batch discovery targets (Account Numbers, '
              'IP Addresses, or URLs). This is a file with a line-by-line '
              'list of targets, *not* your json persistence file.'),
        type=lambda pth: os.path.realpath(os.path.expanduser(pth)))
    batch_discover_parser.add_argument(
        '--tags', nargs='+', type=str, required=True, metavar='TAG',
        help='Tags for this batch discovery job')
    batch_discover_parser.add_argument(
        '--seed-tags', nargs='+', type=str,
        help='Load targets from persistence file based on these tags')
    batch_discover_parser.add_argument(
        '--max', type=int, default=50, dest='max_running',
        help='Max number of discoveries running at any given time')
    batch_discover_parser.add_argument(
        '--dont-login', dest='dataplane', action='store_false', default=True,
        help='Do not login to servers')
    batch_discover_parser.set_defaults(func=batch.batch_discovery)

    #
    # ` batch data`
    #
    batch_data_parser = batch_subparsers.add_parser(
        'data', help="Show data from persistence file w/ optional filters.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    batch_data_parser.add_argument(
        '--tags', nargs='+', type=str, metavar='TAG',
        help="Filter by these tags.")
    batch_data_parser.add_argument(
        '--targets', nargs='+', metavar='account_or_netloc',
        help="Filter by these targets (Account Numbers, "
             "IP Addresses, or URLs).")
    batch_data_parser.set_defaults(func=batch.show_persisted_data)
    #
    # ` batch show`
    #
    batch_status_parser = batch_subparsers.add_parser(
        'show', help="Show status on a batch discovery.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    batch_status_parser.add_argument(
        'tags', type=str, nargs='*', metavar='TAG',
        help='Check status of batch discovery with these tags.')
    batch_status_parser.add_argument(
        '--targets', nargs='+', metavar='account_or_netloc',
        help="Filter by these targets (Account Numbers, "
             "IP Addresses, or URLs).")
    batch_status_parser.add_argument(
        '--page', type=int, default=0,
        help='Select page from paginated results')
    batch_status_parser.set_defaults(func=show_batch_status)


def is_netloc(netloc):
    try:
        int(netloc)
        return False
    except ValueError:
        return True
    except TypeError:
        return False


def waldo_from_args(args):
    return client.Waldo(endpoint=args.server, username=args.username,
                        password=args.password, token=args.token,
                        password_from_user=True)


def version(args):
    waldo = waldo_from_args(args)
    version = waldo.version()
    print("Client version:", version['client'])
    print("Server version:", version['server'])


def create_discovery(args):
    waldo = waldo_from_args(args)
    vers = waldo.version()
    print("Client version:", vers['client'])
    print("Server version:", vers['server'])


def purge_persistence_file(args):

    return batch.purge_persistence_file(
        args.persistence_file, targets=args.targets, tags=args.tags)


def create_discovery(args):
    waldo_client = waldo_from_args(args)
    print("Discovering", args.account_or_netloc)
    try:
        if is_netloc(args.account_or_netloc):
            discovery = waldo_client.create_discovery(
                netloc=args.account_or_netloc,
                dataplane=args.dataplane)
        else:
            discovery = waldo_client.create_discovery(
                account_number=args.account_or_netloc,
                dataplane=args.dataplane)
    except requests.exceptions.HTTPError, exc:
        exit_http_exception(exc)

    print("UI:  %s%s%s" % (args.server, '/ui/discoveries/', discovery['id']))
    print("API: http GET %s%s%s X-Auth-Token:%s" % (
        args.server, '/v1/discoveries/', discovery['id'], waldo_client.token))


def show_batch_status(args):
    if not args.tags and hasattr(show_batch_status, '_parser'):
        show_batch_status._parser.error("At least one tag is required.")

    waldo_client = waldo_from_args(args)
    discoveries = query_discoveries(waldo_client, targets=args.targets,
                                    tags=args.tags, page=args.page)
    persistence_file = batch.PersistenceFile(args.persistence_file)
    persisted = batch.get_persisted_data(persistence_file, args.tags, args.targets)
    records_from_persisted = []
    asyncs = {}
    with futures.ThreadPoolExecutor(50) as pool:
        for trgt, data in persisted.items():
            for tagg, discovery_id in data.iteritems():
                if discovery_id and discovery_id in discoveries['results']:
                    # used waldo-api (source of truth)
                    continue
                if not discovery_id:
                    # not yet triggered
                    records_from_persisted.append(
                        ['Unknown', 'TBD', trgt, tagg, 'NOT YET TRIGGERED'])
                else:
                    # this shouldn't happen, but just in case...
                    fut = pool.submit(
                        waldo_client.get_discovery, discovery_id,
                        include_system_info=False)
                    asyncs[fut] = discovery_id, trgt
        for finished in futures.as_completed(asyncs):
            discovery_id, trgt = asyncs[finished]
            try:
                doc = finished.result()
            except Exception as err:
                LOG.error("Error fetching discovery document %s | %s",
                          discovery_id, err)
                records_from_persisted.append(
                    ['Unknown', discovery_id, trgt, ",".join(args.tags), 'Unknown'])
            else:
                rec = get_tabulated({discovery_id: doc}, with_tags=True)[0]
                records_from_persisted.extend(rec)

    records, headers = get_tabulated(discoveries, with_tags=True)
    records = records + records_from_persisted
    if not all(records.count(elem) == 1 for elem in records):
        for rcrd in copy.deepcopy(records):
            while not records.count(rcrd) == 1:
                records.remove(rcrd)

    print(tabulate(records, headers=headers))

def show_discovery(args):
    waldo = waldo_from_args(args)
    discovery = waldo.get_discovery(args.discovery_id,
                                    args.include_system_info)
    print(json.dumps(discovery, sort_keys=True, indent=4,))


def query_discoveries(waldo_client, targets=None, tags=None, page=None):
    if not targets and not tags:
        raise AttributeError("Requires value for one of 'targets' or 'tags'")
    if targets and not isinstance(targets, list):
        raise TypeError("Targets must be a list.")
    if tags and not isinstance(tags, list):
        raise TypeError("Tags must be a list.")
    netlocs = []
    accts = []
    if targets:
        for trgt in targets:
            if is_netloc(trgt):
                netlocs.append(trgt)
            else:
                accts.append(trgt)
    # api accepts comma separted list of values as possible matches
    netlocs = ",".join(netlocs) or None
    accts = ",".join(accts) or None
    try:
        limit = 200
        offset = page*limit
        return waldo_client.list_discoveries(
            netloc=netlocs, account_number=accts, tags=tags,
            limit=limit, offset=offset)
    except requests.exceptions.HTTPError, exc:
        exit_http_exception(exc)


def get_tabulated(discoveries, with_tags=False):
    records = []
    if 'results' in discoveries:
        discoveries = discoveries['results']

    for discovery_id, data in discoveries.iteritems():
        if not data.get('account'):
            account = 'Unknown'
        else:
            if data['account'].get('source') == 'RAXCLOUD':
                account = "DDI %s" % data['account']['id']
            elif data['account'].get('source') == 'RAXCORE':
                account = "Hybrid %s" % data['account']['id']
            else:
                account = ("Unknown Source %s"
                           % data['account'].get('id') or '?')
        item = [
            account,
            discovery_id,
            data.get('netloc', 'Account') or 'Account',
            data['status'],
            data['time']
        ]

        if with_tags:
            item.insert(-1, ",".join(data['metadata'].get('tags', '')))
        records.append(item)

    headers = ["Account", "Discovery", "Query", "Status", "Timestamp"]
    if with_tags:
        headers.insert(-1, 'Tags')

    records = sorted(records, key=lambda x: x[headers.index('Timestamp')])
    return records, headers


def list_discoveries(args):
    if not args.targets and not args.tags:
        if hasattr(list_discoveries, '_parser'):
            list_discoveries._parser.error(
                "For listing discoveries, at least one of "
                "'targets' or 'tags' is required.")
    waldo_client = waldo_from_args(args)

    discoveries = query_discoveries(waldo_client, targets=args.targets,
                                    tags=args.tags, page=args.page)
    records, headers = get_tabulated(discoveries, with_tags=args.tags)
    print(tabulate(records, headers=headers))



if __name__ == '__main__':
    main()
