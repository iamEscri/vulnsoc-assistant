"""Pace NVD requests and reuse the public KEV catalog inside this process."""
import os
import threading
import time
import requests

_lock=threading.RLock()
_last_nvd=0.0
_kev=None
_kev_until=0.0

def get_json(url, *, params=None, headers=None, timeout=30):
    global _last_nvd, _kev, _kev_until
    with _lock:
        now=time.monotonic()
        if 'services.nvd.nist.gov/' in url:
            interval=0.65 if os.getenv('NVD_API_KEY') else 6.2
            wait=interval-(now-_last_nvd)
            if wait>0:time.sleep(wait)
            _last_nvd=time.monotonic()
        if 'known_exploited_vulnerabilities.json' in url and _kev is not None and now<_kev_until:
            return _kev
        response=requests.get(url,params=params,headers=headers,timeout=timeout)
        response.raise_for_status()
        data=response.json()
        if 'known_exploited_vulnerabilities.json' in url:
            _kev=data;_kev_until=time.monotonic()+1800
        return data
