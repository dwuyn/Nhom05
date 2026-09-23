import unittest
from recursive_json_search import *
from test_data import *

class json_search_test(unittest.TestCase):
    '''test module to test search function in `recursive_json_search.py`'''
    def test_search_found(self):
        '''key should be found, return list should not be empty'''
        self.assertTrue([]!=json_search(key1,data))
    def test_search_not_found(self):
        '''key should not be found, should return an empty list'''
        self.assertTrue([]==json_search(key2,data))
    def test_is_a_list(self):
        '''Should return a list'''
        self.assertIsInstance(json_search(key1,data),list)

    # Security test cases (Yeu cau 5 - dung 3 test cases)
    def test_wrong_role_cannot_read_secret(self):
        '''role khong co quyen khong duoc phep doc apikey'''
        result = json_search("apiKey", data, role="viewer")
        self.assertEqual([], result)

    def test_operator_cannot_read_secret(self):
        '''role operator khong duoc phep doc apikey (chi admin moi co quyen)'''
        result = json_search("apiKey", data, role="operator")
        self.assertEqual([], result)

    def test_viewer_cannot_read_management_ip(self):
        '''role viewer khong duoc phep doc managementIpAddress'''
        result = json_search("managementIpAddress", data, role="viewer")
        self.assertEqual([], result)

if __name__ == '__main__':
    unittest.main()


