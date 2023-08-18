from suds.sudsobject import asdict
import json
import suds

'''
def recursive_asdict(d):
    """Convert Suds object into serializable format."""
    out = {}
    for k, v in asdict(d).iteritems():
        if hasattr(v, '__keylist__'):
            out[k] = recursive_asdict(v)
        elif isinstance(v, list):
            out[k] = []
            for item in v:
                if hasattr(item, '__keylist__'):
                    out[k].append(recursive_asdict(item))
                else:
                    out[k].append(item)
        else:
            out[k] = v
    return out
    
raw = a_suds_response
data = [recursive_asdict(t) for t in raw]
out = json.dumps(data)
'''

def recursive_asdict(d):
    """Convert Suds object into serializable format."""
    out = {}
    for k, v in asdict(d).items():
        if hasattr(v, '__keylist__'):
            out[k] = recursive_asdict(v)
        elif isinstance(v, list):
            out[k] = []
            for item in v:
                if hasattr(item, '__keylist__'):
                    out[k].append(recursive_asdict(item))
                elif not isinstance(item, list):
                    out[k] = item
                else:
                    out[k].append(item)
        else:
            out[k] = v
    return out

def suds_to_json(data):
    if not isinstance(data, suds.sudsobject.Object): # isinstance(data, dict):
        return json.dumps(data, ensure_ascii=False, default=str)
    else:
        return json.dumps(recursive_asdict(data), ensure_ascii=False, default=str)