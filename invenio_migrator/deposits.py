# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2016 CERN.
#
# Invenio is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.
#
# Invenio is distributed in the hope that it will be
# useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Invenio; if not, write to the
# Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston,
# MA 02111-1307, USA.
#
# In applying this license, CERN does not
# waive the privileges and immunities granted to it by virtue of its status
# as an Intergovernmental Organization or submit itself to any jurisdiction.

"""Deposit dump and dump loader."""

from __future__ import absolute_import, print_function

from os.path import splitext
from flask import current_app
import arrow
from dojson.contrib.marc21 import marc21
from dojson.contrib.marc21.utils import create_record
from invenio_accounts.models import User
from invenio_db import db
from invenio_files_rest.models import Bucket, BucketTag, FileInstance, \
    ObjectVersion
from invenio_pidstore.errors import PIDDoesNotExistError
from invenio_pidstore.models import PersistentIdentifier, PIDStatus, \
    RecordIdentifier
from invenio_pidstore.resolver import Resolver
from invenio_records.api import Record
from invenio_records_files.models import RecordsBuckets
from invenio_sipstore.models import SIP, RecordSIP, SIPFile
from werkzeug.utils import cached_property


class DepositDumpLoader(object):
    """Migrate a deposit.

    Uses Record API in order to bypass all Deposit-specific initialization,
    which are to be done after the final stage of deposit migration.
    """

    @classmethod
    def create(cls, dump):
        """Create deposit based on dump."""
        deposit = cls.create_record(dump)
        depid, recid = cls.create_pids(dump, deposit)
        bucket, files = cls.create_files(dump, deposit)
        cls.create_sips(dump, deposit, files, recid)
        cls.create_meta(dump, deposit, depid, recid, bucket, files)
        if depid.status == PIDStatus.DELETED:
            cls.delete_record(deposit, bucket)
        else:
            cls.update_bucket(deposit, bucket)
        return (deposit, depid)

    @classmethod
    def create_record(cls, dump):
        """Create a new record from dump."""
        deposit = Record.create(data=dump.data)
        deposit.model.created = dump.created
        deposit.commit()
        return deposit

    @classmethod
    def create_pids(cls, dump, deposit):
        """Create a persistent identifiers."""
        # Mark deposit deleted if recid is deleted.
        recid = dump.recid_pid
        # Create depid
        depid = PersistentIdentifier.create(
            pid_type='depid',
            pid_value=str(dump.depid),
            object_type='rec',
            object_uuid=deposit.id,
            status=PIDStatus.REGISTERED
        )
        if recid and recid.status == PIDStatus.DELETED:
            depid.delete()
        if RecordIdentifier.query.get(dump.depid) is None:
            RecordIdentifier.insert(dump.depid)

        # Pre-reserved recid.
        if not recid and dump.recid:
            if dump.has_pid:
                # Published deposit without a recid (this is an upload which
                # never got ingested so we set it back to draft status and
                # reserves the reid).
                pass
            recid = PersistentIdentifier.create(
                pid_type='recid',
                pid_value=str(dump.recid),
                status=PIDStatus.RESERVED
            )
            if RecordIdentifier.query.get(dump.recid) is None:
                RecordIdentifier.insert(dump.recid)

        return depid, recid

    @classmethod
    def create_files(cls, dump, deposit):
        """Create files."""
        # Create bucket and link to deposit.
        bucket = Bucket.create()
        db.session.add(
            RecordsBuckets(record_id=deposit.id, bucket_id=bucket.id)
        )

        files = []
        for f in dump.files:
            files.append(cls.create_file(bucket, f))

        return bucket, files

    @classmethod
    def create_file(self, bucket, f):
        """Create a single file."""
        # Ensure that file instance get's created with the same ID as it is
        # used in the REST API.
        fileinstance = FileInstance(
            id=f['id'],
            writable=True,
            readable=False,
            size=0,
        )
        db.session.add(fileinstance)
        fileinstance.set_uri(f['uri'], f['size'], f['checksum'])

        obj = ObjectVersion.create(bucket, f['key']).set_file(fileinstance)

        return (dict(
            bucket=str(obj.bucket.id),
            key=obj.key,
            checksum=obj.file.checksum,
            size=obj.file.size,
            version_id=str(obj.version_id),
            type=f['type'],
        ), fileinstance)

    @classmethod
    def create_sips(cls, dump, deposit, files, recid):
        """Create submission information packages."""
        if not recid or recid.status == PIDStatus.RESERVED:
            return
        first = True
        for s in dump.sips:
            # Create SIP
            sip = SIP.create(
                s['format'],
                s['content'],
                user_id=s['user_id'],
                agent=s['agent'],
                id_=s['id'],
            )
            sip.created = s['timestamp']

            # Create SIP files only for first package.
            if first:
                first = False
                for meta, f in files:
                    db.session.add(SIPFile(
                        sip_id=sip.id, filepath=meta['key'], file_id=f.id
                    ))

            # PID - SIP relationship
            db.session.add(RecordSIP(sip_id=sip.id, pid_id=recid.id))

    @classmethod
    def create_meta(self, dump, deposit, depid, recid, bucket, files):
        """Create deposit metadata."""
        deposit['_n'] = {
            '_buckets': {'deposit': str(bucket.id)},
            '_deposit': {
                'created_by': dump.user.id if dump.user else None,
                'owners': [dump.user.id] if dump.user else None,
                'id': depid.pid_value,
            },
            '_files': [x[0] for x in files],
        }

        # If deposit has been submitted, set status, pid and _buckets
        # correctly.
        status = 'draft'
        if recid and recid.status == PIDStatus.REGISTERED:
            record = Record.get_record(recid.object_uuid)
            if not dump.is_draft:
                status = 'published'

            # Create PID
            pid = {
                'type': 'recid',
                'value': recid.pid_value,
            }
            if status == 'draft':
                pid['revision_id'] = record.revision_id
            deposit['_n']['_deposit']['pid'] = pid

            # Set buckets in both deposit and record.
            # ~21 records have no bucket.
            if '_buckets' not in record:
                record_bucket = Bucket.create()
                record_bucket.locked = True
                db.session.add(RecordsBuckets(
                    record_id=recid.object_uuid, bucket_id=record_bucket.id))
                record.setdefault('_buckets', {})
                record['_buckets']['record'] = str(record_bucket.id)

            deposit['_n']['_buckets']['record'] = record['_buckets']['record']
            record['_buckets']['deposit'] = \
                deposit['_n']['_buckets']['deposit']
            record.commit()
        deposit['_n']['_deposit']['status'] = status
        deposit.commit()

    @classmethod
    def delete_record(cls, deposit, bucket):
        """Delete a record if needed."""
        deposit.delete()
        bucket.deleted = True

    @classmethod
    def update_bucket(cls, deposit, bucket):
        """Update bucket."""
        if 'pid' in deposit['_n']['_deposit']:
            bucket.locked = True
        bucket.quota_size = current_app.config['ZENODO_BUCKET_QUOTA_SIZE']
        bucket.max_file_size = current_app.config['ZENODO_MAX_FILE_SIZE']


class DepositDump(object):
    """Deposit dump wrapper.

    Wrapper around a deposit dump, with tools for loading the dump. Extend this
    class to provide custom behavior for loading of deposit dumps.
    """

    def __init__(self, data):
        """Initialize class."""
        self.data = data

    @cached_property
    def created(self):
        """Get creation timestamp."""
        return arrow.get(
            self.data['_p']['created']).datetime.replace(tzinfo=None)

    @cached_property
    def depid(self):
        """Get deposit id."""
        return self.data['_p']['id']

    @cached_property
    def recid(self):
        """Get recid (either from SIP or prereserved property)."""
        # First look in an already created SIP
        recids = [int(sip['metadata']['recid']) for sip in self.sips]
        if len(set(recids)) > 1:
            raise Exception(
                "Multiple recids in sips for depid {0}".format(self.depid))
        elif recids:  # If only one recid
            return int(recids[0])

        if 'drafts' in self.data:
            if len(self.data['drafts']) == 0:
                return None
            elif len(self.data['drafts']) != 1:
                raise Exception(
                    'Deposit {0} has multiple drafts'.format(self.depid))

            values = self.data['drafts'].values()[0]['values']
            if 'prereserve_doi' in values:
                return int(values['prereserve_doi']['recid'])

        return None

    @cached_property
    def recid_pid(self):
        if not self.recid:
            return None

        try:
            return PersistentIdentifier.get('recid', str(self.recid))
        except PIDDoesNotExistError:
            return None

    @cached_property
    def user_id(self):
        """User ID for deposit."""
        return int(self.data['_p']['user_id'])

    @cached_property
    def user(self):
        """User for deposit."""
        return User.query.filter_by(id=self.user_id).one_or_none()

    @cached_property
    def files(self):
        """Get files."""
        res = {}
        for f in self.data.pop('files', []):
            ext = splitext(f['name'])[1].lower()
            ext = ext[1:] if ext.startswith('.') else ext
            if f['name'] in res:
                # Is it not the same file? strip md5 from checksum
                if res[f['name']]['checksum'][4:] != f['checksum']:
                    raise Exception(
                        'File {0} already exists in depid {1}'.format(
                            f['name'], self.depid)
                    )
                else:
                    continue
            res[f['name']] = dict(
                id=f['id'],
                size=f['size'],
                key=f['name'],
                checksum='md5:{0}'.format(f['checksum']),
                type=ext,
                uri=f['path'],
            )
        return res.values()

    @cached_property
    def sips(self):
        """Get submission information packages."""
        def _sip_user_id(user_id):
            if not user_id:
                return None
            if self.user_id == user_id:
                return self.user.id if self.user else None
            else:
                u = User.query.filter_by(id=user_id).one_or_none()
                return u.id if u else None

        res = []
        for sip in self.data['sips']:
            agent = sip['agents'][0] if sip['agents'] else {}
            user_id = _sip_user_id(agent.get('user_id'))
            ip = agent.get('ip_address')
            email = agent.get('email_address')
            timestamp = arrow.get(
                    sip['timestamp']).datetime.replace(
                        tzinfo=None
                    ) if sip['timestamp'] else None
            # We don't create SIPs in new system for unsealed SIPs as they were
            # not formally submitted.
            if not timestamp:
                continue

            res.append(dict(
                id=sip['id'],
                user_id=user_id,
                timestamp=timestamp,
                sealed=timestamp is not None,
                agent=dict(
                    ip_address=ip or '',
                    email=email or '',
                ) if ip or email else None,
                format='marcxml',
                content=sip['package'],
                metadata=sip['metadata'],
            ))
        return res

    @cached_property
    def is_draft(self):
        """Check if dump is in draft mode."""
        # TODO: Validate this one. E.g. no-drafts in depid 1925 - but in
        # draftmode
        drafts = self.data['drafts']
        # If no draft at all, or more than one draft or draft by completed
        if not drafts or len(drafts) > 1 or \
                list(drafts.values())[0]['completed']:
            return False
        else:
            return True

    @cached_property
    def has_pid(self):
        """Check if deposit has been already published before."""
        return self.data['_p']['submitted']
