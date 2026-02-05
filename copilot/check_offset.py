#!/usr/bin/env python3
import dis

def safe_access():
    x = get_list()
    return x[1]

dis.dis(safe_access)
