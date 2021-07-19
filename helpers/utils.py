import socket
import os
import logging
import validators
from datetime import datetime, timedelta
import nmap
import json
from enum import Enum

from helpers.mongo_connection import db
from helpers.requests_retry import retry_session
from helpers import common_strings


def validate_domain(domain):
    if not validators.domain(domain):
        return False
    else:
        return True


def check_force(data, force, collection, timeframe):
    if force:
        return True
    db[collection].create_index(common_strings.strings['mongo_value'])
    search = db[collection].find_one({common_strings.strings['mongo_value']: data})

    if search is not None:
        if search['status'] == common_strings.strings['status_running'] or \
                search['status'] == common_strings.strings['status_queued']:
            return search['status']
        else:
            force = search['timeStamp'] + timedelta(days=timeframe) < datetime.utcnow()

    if force is False and search is not None:
        return search
    else:
        return True


def mark_db_request(value, status, collection):
    try:
        db[collection].update_one({common_strings.strings['mongo_value']: value}, {'$set': {'status': status}},
                                  upsert=True)
    except Exception as e:
        logger = logging.getLogger(collection)
        logger.critical(common_strings.strings['database_issue'], e)
    return True


def v1_format_by_ip(sub_domains, out_format):
    out_dict = {}
    out_list = []
    out_blacklist = []
    blacklist_dict = {}
    out_sub_domain_count = 0

    blacklist = ['.nat.']

    for each_domain in sub_domains:
        try:
            ip = socket.gethostbyname(each_domain)  # we don't need to display sub-domains that do not have an IP
            for each_item in blacklist:
                if each_item in each_domain:
                    if each_item in blacklist_dict:
                        blacklist_dict[each_item] += 1
                    else:
                        blacklist_dict[each_item] = 1
                    break
            else:
                out_sub_domain_count += 1
                if out_format:
                    if ip in out_dict:
                        out_dict[ip] += [each_domain]
                    else:
                        out_dict[ip] = [each_domain]
                else:
                    out_list.append(each_domain)
        except:
            pass

    for each_blacklist in blacklist_dict:
        out_blacklist.append({'count': blacklist_dict[each_blacklist],
                              'reason': f"Blacklisted because the sub-domain contains '{each_blacklist}'"})

    if out_format:
        return out_dict, out_blacklist, out_sub_domain_count
    else:
        return out_list, out_blacklist, out_sub_domain_count


