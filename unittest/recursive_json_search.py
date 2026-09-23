from test_data import *
try:
    from policy import POLICY
except ImportError:
    from unittest.policy import POLICY


def json_search(key, input_object, role=None):
    """
    Search for a key in a nested JSON object (dict or list) and return
    a list of matching key-value pairs (as dictionaries {key: value}),
    enforcing role-based access control based on policy.py.
    """
    ret_val = []

    # Enforce role-based access control based on policy.py
    if key not in POLICY or role not in POLICY.get(key, []):
        return ret_val

    if isinstance(input_object, dict):
        for k, v in input_object.items():
            if k == key:
                temp = {k: v}
                ret_val.append(temp)
            if isinstance(v, dict):
                ret_val.extend(json_search(key, v, role=role))
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, (dict, list)):
                        ret_val.extend(json_search(key, item, role=role))
    elif isinstance(input_object, list):
        for item in input_object:
            if isinstance(item, (dict, list)):
                ret_val.extend(json_search(key, item, role=role))

    return ret_val


if __name__ == '__main__':
    print(json_search("issueSummary", data, role="admin"))
