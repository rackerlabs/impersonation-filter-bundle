#!/bin/bash

# Safely add the user/group.
getent passwd repose >> /dev/null 2>&1 || adduser --system --no-create-home --group repose
exit 0