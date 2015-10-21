#!/bin/bash

# Safely delete the user/group.
getent passwd repose >> /dev/null 2>&1 && deluser --system repose
exit 0