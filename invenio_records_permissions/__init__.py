# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 CERN.
#
# Invenio-Records-Permissions is free software; you can redistribute it
# and/or modify it under the terms of the MIT License; see LICENSE file for
# more details.

"""Invenio module for role based access control to records."""

from __future__ import absolute_import, print_function

from .ext import InvenioRecordsPermissions
from .version import __version__

__all__ = ('__version__', 'InvenioRecordsPermissions')
