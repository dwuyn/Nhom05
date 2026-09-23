import unittest
try:
    from recursive_json_search import json_search
    from test_data import data, key1, key2
    from policy import POLICY
except ImportError:
    from unittest.recursive_json_search import json_search
    from unittest.test_data import data, key1, key2
    from unittest.policy import POLICY


class json_search_test(unittest.TestCase):
    '''test module to test search function in `recursive_json_search.py`'''

    def test_search_found(self):
        '''key should be found, return list should not be empty'''
        self.assertTrue([] != json_search(key1, data, role="viewer"))

    def test_search_not_found(self):
        '''key should not be found, should return an empty list'''
        self.assertTrue([] == json_search(key2, data, role="admin"))

    def test_is_a_list(self):
        '''Should return a list'''
        self.assertIsInstance(json_search(key1, data, role="viewer"), list)

    def test_apiKey_restricted_to_admin_only(self):
        '''apiKey should be accessible only by admin, blocked for operator and viewer'''
        # Admin can access apiKey
        admin_result = json_search("apiKey", data, role="admin")
        self.assertTrue([] != admin_result)
        self.assertEqual(admin_result, [{"apiKey": "SNMP-COMMUNITY-STRING-7f3a9c"}])

        # Operator cannot access apiKey
        self.assertEqual([], json_search("apiKey", data, role="operator"))

        # Viewer cannot access apiKey
        self.assertEqual([], json_search("apiKey", data, role="viewer"))

    def test_managementIpAddress_blocked_for_viewer(self):
        '''managementIpAddress should be accessible by admin and operator, blocked for viewer'''
        # Admin can access managementIpAddress
        admin_result = json_search("managementIpAddress", data, role="admin")
        self.assertTrue([] != admin_result)
        self.assertEqual(admin_result, [{"managementIpAddress": "10.10.20.21"}])

        # Operator can access managementIpAddress
        operator_result = json_search("managementIpAddress", data, role="operator")
        self.assertTrue([] != operator_result)
        self.assertEqual(operator_result, [{"managementIpAddress": "10.10.20.21"}])

        # Viewer cannot access managementIpAddress
        self.assertEqual([], json_search("managementIpAddress", data, role="viewer"))

    def test_default_deny_when_role_is_none_or_invalid(self):
        '''Default deny should return empty list when role is None, empty, or invalid'''
        # When role is None or omitted
        self.assertEqual([], json_search("apiKey", data, role=None))
        self.assertEqual([], json_search("managementIpAddress", data, role=None))
        self.assertEqual([], json_search("issueSummary", data, role=None))
        self.assertEqual([], json_search("issueSummary", data))

        # When role is invalid or unrecognized
        self.assertEqual([], json_search("apiKey", data, role="guest"))
        self.assertEqual([], json_search("managementIpAddress", data, role="guest"))
        self.assertEqual([], json_search("issueSummary", data, role="guest"))
        self.assertEqual([], json_search("issueSummary", data, role=""))
        self.assertEqual([], json_search("issueSummary", data, role="unknown_role"))

    def test_wrong_role_cannot_read_secret(self):
        '''Calling json_search with an insufficient role returns an empty list'''
        result = json_search("apiKey", data, role="viewer")
        self.assertEqual([], result)


if __name__ == '__main__':
    unittest.main()
