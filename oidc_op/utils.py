import datetime
import pytz


def timestamp2dt(value):
    return int(datetime.datetime.timestamp(value))

def dt2timestamp(value):
    ts = pytz.utc.localize(datetime.datetime.fromtimestamp(value))
