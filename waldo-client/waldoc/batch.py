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

"""Batch discovery execution and management."""

from __future__ import print_function

import atexit
import copy
import datetime
try:
    # ujson is 5x-10x faster
    import ujson as json
except ImportError:
    import json
import logging
import os
import Queue
import re
import sys
import time

from concurrent import futures
import requests

from waldoc import client

LOG = logging.getLogger(__name__)


class DiscoveryMonitorTimeoutError(Exception):

    """Discovery is considered stale, something probably went wrong."""


class PersistenceFile(object):

    """Wrapper for the batch discovery JSON persistence file.

    Default file location in shell.py:
        ~/.waldo_batch_discoveries.json

    May include a thread-safe queue for passing data
    in the form below (schema).

    Tuples will be formatted to json according to the schema
    of the peristence file upon calling self.write_queued()

    Schema:
        {
            <netloc_or_account_number0>: {
                <tag0>: <discovery_id0>,
                <tag1>: <discovery_id1>,
            }
            <netloc_or_account_number1>: {
                <tag0>: <discovery_id0>,
                <tag1>: <discovery_id1>,
            }
        }

    P.S. - 'synq' -> Synchronized Queue
    """
    def __init__(self, path, writer_queue=None):
        """Initialize using path to file and optional thread-safe queue.

        Queue is used for json serializable data to be written to file when
        self.write_queued() is called.

        If the file at 'path' doesn't exist it will be created.
        """

        self.path = os.path.realpath(os.path.expanduser(path))
        if not os.path.exists(self.path):
            print("Persistence file %s does not exist yet, creating it...")
            json.dump({}, open(self.path, 'w'))
        else:
            # check for json-ness
            try:
                json.load(open(self.path))
                LOG.debug("Loaded existing persistence file %s.",
                          os.path.relpath(self.path))
            except ValueError as err:
                raise ValueError("The persistence file -> %s is not "
                                 "a valid json file. | %s"
                                 % (os.path.relpath(self.path), err))
        if writer_queue and not isinstance(writer_queue, Queue.Queue):
            raise TypeError('writer_queue should be a Queue.Queue.')
        elif writer_queue:
            self.synq = writer_queue
            self.synq._persisted = set()
        else:
            self.synq = None

    def load(self):
        """Return the deserialized json object."""
        return json.load(open(self.path))

    def save(self, data):
        """Save data to file.

        Careful, this overwrites any existing data on file.
        Use self.udpate() to perform partial updates.
        """
        json.dump(data, open(self.path, 'w'))

    def set_queue(self, writer_queue=None):
        """Provide a queue or have one created for you.

        Always return the queue and set it as self.synq
        """
        if writer_queue and not isinstance(writer_queue, Queue.Queue):
            raise TypeError('writer_queue should be a Queue.Queue.')
        elif not writer_queue:
            writer_queue = Queue.Queue()
        self.synq = writer_queue
        return self.synq

    def get_queue(self):
        """Return the queue associated with this file wrapper."""
        if not self.synq:
            raise AttributeError("No queue specified, set one with "
                                 "self.set_queue(Queue...)")
        return self.synq

    def write_queued(self):
        """Write data from the backing synchronized queue the file."""
        if not self.synq:
            raise AttributeError("No queue specified, set one with "
                                 "self.set_queue(Queue...)")
        towrite = {}
        while not self.synq.empty():
            try:
                towrite.update(self.synq.get_nowait())
            except Queue.Empty:
                pass
        return self.update(towrite)

    def update(self, data):
        """Perform a friendly update of the json on file.

        Works like a dictionary-merge going 1 level deep.

        Ex:

        existing file  # persistence.json
        ---------------------------------
        # persistence.json
        {
            'target_a': {
                'tag_1': 'uuid_abc',
            }
        }

        self.update({'target_a': {'tag_2': 'uuid_xyz'},
                     'target_b': {'tag_1': 'uuid_def'}})

        The 'target_a' dictionary will be merged, and
        target_b would be added, resulting in:

        updated file  # persistence.json
        --------------------------------
        {
            'target_a': {
                'tag_1': 'uuid_abc',
                'tag_2': 'uuid_xyz',
            },
            'target_b': {
                'tag_1': 'uuid_def',
            }
        }

        """
        updating = self.load()
        check_delta = copy.deepcopy(updating)
        for target, document in data.iteritems():
            if target in updating and document != updating[target]:
                LOG.debug("Updating existing target %s record in persistence file "
                          "with tags: %s", target, document.keys())
                updating[target].update(document)
            elif target in updating and document == updating[target]:
                # nothing to update
                continue
            else:
                LOG.debug("Adding target %s to persistence file.", target)
                updating[target] = document
        # only open/write file if there are changes
        if updating != check_delta:
            self.save(updating)

    def purge(self):
        """Replace all data on file with an empty object, '{}'."""
        decision = raw_input("\nAre you sure you want to reset your "
                             "persistence file %s? "
                             % os.path.relpath(self.path))
        if not 'y' in decision.lower():
            print("Aborting purge.")
            return
        self.save({})

    def remove(self, targets=None, tags=None):
        """Remove items from persisted data which match tags or targets."""
        if not targets and not tags:
            raise AttributeError(
                "No 'targets' or 'tags' specified for removal.")
        persisted = self.load()
        # create object that is the loaded data minus tags and targets and re-write it
        excluding = {}
        removed = 0
        for trgt, data in persisted.items():
            if targets and trgt in targets:
                # skip the entire target
                removed += len(data)
                continue
            excluding[trgt] = data
            for tag in data.iterkeys():
                if tags and tag in tags:
                    # remove selected tags
                    if excluding[trgt].pop(tag, None):
                        removed += 1
                    continue
        remaining = sum((len(k) for k in excluding.values()))
        print("Removed %s items, leaving %s remaining."
              % (removed, remaining))
        self.save(excluding)


    def list_targets_by_tags(self, seedtags):
        """Load list of targets from persistence file based on tags."""
        loaded = self.load()
        matched_targets = [k for k, v in loaded.iteritems()
                           if all(j in v for j in seedtags)]
        if not matched_targets:
            raise StandardError("No existing targets found in persistence file "
                                "from tags: '%s'", "', '".join(seedtags))
        return matched_targets


def is_netloc(netloc):
    try:
        int(netloc)
        return False
    except ValueError:
        return True


def to_datetime(time_string):
    """Convert standard time string to a datetime object."""
    try:
        return datetime.datetime.strptime(
            time_string, '%Y-%m-%d %X %z')
    except ValueError:
        time_string = time_string[:-5].strip()
    return datetime.datetime.strptime(
        time_string, '%Y-%m-%d %X')


def from_targets_file(targets_file):
    """Load targets from file."""
    if not os.path.exists(targets_file):
        raise ValueError("Targets file %s does not exist.",
                         os.path.relpath(targets_file))
    else:
        with open(targets_file, 'rU') as tfile:
            targets = list({m.strip() for k in tfile.readlines()
                            for m in k.split() if m.strip()})
            for target in copy.copy(targets):
                if target.startswith('#'):
                    targets.remove(target)
                    continue
                if '.' not in target and ':' not in target:
                    try:
                        int(target)
                    except StandardError:
                        targets.remove(target)
    if not targets:
        raise ValueError("No targets were found in file %s.",
                         os.path.relpath(targets_file))
    else:
        print("Loaded targets from file %s" % targets_file)
    return targets


def should_skip(target, tags, persistence_file):
    """Find existing discovery id with matching target and tags."""
    persisted_data = persistence_file.load().get(target)
    if persisted_data:
        discovery_id = {persisted_data.get(t) for t in tags}
        if all(discovery_id) and len(discovery_id) == 1:
            return discovery_id.pop()
        # a single discovery must match *all* tags for should_skip
        # to return a discovery id


def purge_persistence_file(persistence_file, targets=None, tags=None):

    if not os.path.exists(persistence_file):
        raise ValueError("Persistence file %s does not exist. "
                         "Nothing to purge."
                         % os.path.relpath(persistence_file))
    persistence_file = PersistenceFile(persistence_file)
    if not targets and not tags:
        persistence_file.purge()
    else:
        persistence_file.remove(targets=targets, tags=tags)


def get_persisted_data(persistence_file, tags=None, targets=None):

    if not isinstance(persistence_file, PersistenceFile):
        raise TypeError(
            "persistence_file should be an instance of PersistenceFile")
    loaded = persistence_file.load()
    if targets:
        loaded = {j: k for j, k in loaded.items()
                  if j in targets}
    if tags:
        loaded = {j: k for j, k in loaded.items()
                  if all(tag in k for tag in tags)}
        for data in loaded.itervalues():
            for tag in data.copy().iterkeys():
                if tag not in tags:
                    data.pop(tag, None)
    return loaded


def show_persisted_data(args):

    persistence_file = PersistenceFile(args.persistence_file)
    loaded = get_persisted_data(persistence_file, args.tags, args.targets)
    import json as orig_json
    print(orig_json.dumps(loaded, sort_keys=True, indent=4))

def batch_discovery(args):
    """Run, manage, and monitor a batch discovery."""

    pfile_queue = Queue.Queue()
    persistence_file = PersistenceFile(args.persistence_file,
                                       writer_queue=pfile_queue)

    if args.targets:
        targets = args.targets
    elif args.targets_file:
        targets = from_targets_file(args.targets_file)
    else:
        if not args.seed_tags:
            decision = raw_input(
                "\nNo --seed-tags, --targets, or --targets-file provided. "
                "Continue using current tag(s) -> %s as seed tags for new "
                "batch discovery? ( To see which targets this implies, run "
                "`waldo batch data --tags %s` ) "
                % (args.tags, " ".join(args.tags)))
            if not 'y' in decision.lower():
                print("Aborting batch discovery.")
                return
            else:
                new_tag_name = raw_input(
                    "%s will be used as seed tag(s). Now you need new tag "
                    "name: " % args.tags)
                if not new_tag_name:
                    print("Invalid tag name. Aborting.")
                else:
                    args.seed_tags = args.tags
                    args.tags = [j.strip()
                                 for j in re.split(r'\W+', new_tag_name)]
        targets = persistence_file.list_targets_by_tags(
            args.seed_tags or args.tags)

    assert targets, "No targets (netlocs or account numbers) provided"
    waldo_client = client.Waldo(args.username, password=args.password,
                                token=args.token, password_from_user=True)

    store = {}
    job_queue = {}
    with futures.ThreadPoolExecutor(args.max_running) as pool:
        ensure_streamhandler()
        try:
            while targets:
                selected = targets.pop()
                LOG.debug("Looking at %s. Targets remaining: %s",
                          selected, len(targets))
                # should_skip returns the discovery_id if we already have one
                # for this target/tags combo
                shouldskip = should_skip(selected, args.tags,
                                         persistence_file)
                if shouldskip:
                    store[selected] = {tag: shouldskip for tag in args.tags}
                    fut = pool.submit(monitor_discovery, shouldskip, waldo_client)
                    atexit.register(fut.cancel)
                    print("Monitoring existing discovery %s for "
                          "target %s with tag(s): %s"
                          % (shouldskip, selected, args.tags))
                else:
                    store[selected] = {tag: None for tag in args.tags}
                    fut = pool.submit(create_and_monitor_discovery, selected,
                                      waldo_client, args.dataplane, args.tags,
                                      persistence_file.synq)
                    atexit.register(fut.cancel)
                    print("Triggered discovery (dataplane: %s) for "
                          "target %s with tag(s): %s"
                          % (args.dataplane, selected, args.tags))
                persistence_file.update(store)
                time.sleep(.25)

                job_queue[fut] = selected
            atexit.register(pool.shutdown, wait=False)
            return manage_job_queue(job_queue, persistence_file)
        except KeyboardInterrupt:
            print("\nShutting down threadpool...")
            for job in job_queue:
                job.cancel()
            pool.shutdown(wait=False)
            sys.exit('KeyboardInterrupt')


def manage_job_queue(job_queue, persistence_file):

    results = {}
    oldstats = {}
    while not all(k._state == 'FINISHED' for k in job_queue):
        # create a dict of stats using Futures in job_queue
        # print them when each loop only if they've changed
        persistence_file.write_queued()
        time.sleep(1)
        states = [job._state for job in job_queue]
        newstats = {_state: states.count(_state) for _state in set(states)}
        if newstats != oldstats:
            import json as orig_json
            print("Job queue stats:")
            print(orig_json.dumps(newstats, sort_keys=True, indent=4))
        oldstats = newstats
        finished = [j for j in job_queue if j._state == 'FINISHED'
                    and job_queue[j] not in results]
        for job in finished:
            try:
                result = job.result()
            except Exception as err:
                print(err)
                result = err
                did = 'unknown'
                dstatus = "%s: %s" % (err.__class__.__name__, err)
            else:
                did = result['id']
                dstatus = result['status']
            trgt = job_queue[job]
            results[trgt] = result
            print("%s finished. Status: %s  ID: %s"
                  % (trgt, dstatus, did))


    for job, target in job_queue.iteritems():
        try:
            result = job.result()
        except Exception as err:
            print(err)
            result = err
        results[target] = result

    return results


class CurrentFileFilter(logging.Filter):
    """Only emit logs originating in this file."""

    name = "%s Logging Filter" % os.path.relpath(__file__)

    def filter(self, logrecord):
        """Filter logs which don't originate in this file."""
        if os.path.realpath(logrecord.pathname) != os.path.realpath(__file__):
            return False
        return True

_CURRENTFILEFILTER = CurrentFileFilter()
CurrentFileFilter = lambda: _CURRENTFILEFILTER


def ensure_streamhandler(level=logging.INFO):
    """Ensure that a StreamHandler to stdout is attached to root logger."""

    cffilt = CurrentFileFilter()
    frmt = logging.Formatter(fmt='%(asctime)s: %(message)s')
    rootlogger = logging.getLogger()
    if not rootlogger.isEnabledFor(level):
        rootlogger.setLevel(level)
    for hand in rootlogger.handlers:
        if isinstance(hand, logging.StreamHandler):
            if hand.level < level:
                hand.setLevel(level)
            if hand.stream != sys.stdout:
                hand.stream = sys.stdout
            hand.addFilter(cffilt)
            hand.setFormatter(frmt)
            break
    else:
        console = logging.StreamHandler(stream=sys.stdout)
        console.setLevel(level)
        console.set_name('Batch discovery stdout streamhandler')
        console.addFilter(cffilt)
        console.setFormatter(frmt)
        rootlogger.addHandler(console)


def create_and_monitor_discovery(target, waldo_client, dataplane,
                                 tags, pfqueue):
    """Return discovery only after Waldo has finished it.

    Since this function is often ran in a separate thread, we will rely on
    the logging module to get messages to stdout, so ensure_streamhandler()
    is always called when the function runs.
    """
    try:
        if is_netloc(target):
            discovery = waldo_client.create_discovery(netloc=target,
                                                      dataplane=dataplane,
                                                      tags=tags)
        else:
            discovery = waldo_client.create_discovery(account_number=target,
                                                      dataplane=dataplane,
                                                      tags=tags)
        rttags = discovery['metadata'].get('tags')
        assert rttags == tags
        assert bool(discovery['dataplane']) == bool(dataplane)
    except requests.exceptions.HTTPError as err:
        LOG.error("Error requesting discovery on target %s | %s",
                  target, err)
        raise
    else:
        if discovery['id'] not in pfqueue._persisted:
            pfqueue.put({target: {t: discovery['id'] for t in rttags}})
            pfqueue._persisted.add(discovery['id'])
        LOG.info("Successfully triggered discovery for target %s. "
                 "Monitoring for this discovery begins now.", target)
        return monitor_discovery(discovery['id'], waldo_client)


def monitor_discovery(discovery_id, waldo_client, timeout=60*60, wait=5):
    """Monitor discovery with a default timeout of 1 hour.

    If timestamp on discovery is observed to be older than 'timeout' seconds,
    raise DiscoveryMonitorTimeoutError.

    Since this function is often ran in a separate thread, we will rely on
    the logging module to get messages to stdout, so ensure_streamhandler()
    is always called when the function runs.
    """
    discovery = None
    try:
        discovery = waldo_client.get_discovery(
            discovery_id, include_system_info=False)
    except (ValueError, TypeError) as err:
        LOG.error("Failed to decode or fetch discovery %s. Will retry. | %s",
                  discovery_id, str(err))
    else:
        if discovery and (discovery['status']
                          not in ['REQUESTED', 'PENDING']):
            return discovery
        else:
            # check for staleness
            dtime = to_datetime(discovery['time'])
            age = datetime.datetime.utcnow() - dtime
            if age > datetime.timedelta(seconds=timeout):
                raise DiscoveryMonitorTimeoutError(
                    "Giving up on discovery of age %s" % age)
            # else retry
    time.sleep(wait)
    return monitor_discovery(discovery_id, waldo_client,
                             timeout=timeout, wait=wait)
