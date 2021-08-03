import yaml
import ipaddress
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper


class SanityManager:
    def __init__(self, test_case_file, ):
        self.case = yaml.load(open(test_case_file, 'r'), Loader=Loader)
        try:
            self.__check_case()
        except RuntimeError as e:
            raise RuntimeError('failed to parse test case') from e

    def __check_case(self):
        side_1 = self.case.get('side_1')
        if not side_1:
            raise RuntimeError('missing side_1 definition')

        side_2 = self.case.get('side_2')
        if not side_2:
            raise RuntimeError('missing side_2 definition')

        __check_ip_port('side_1', side_1.get('ip'), side_1.get('port'))
        __check_ip_port('side_2', side_2.get('ip'), side_2.get('port'))


def __check_ip_port(side, ip, port):
    if not ip or not port:
        raise RuntimeError('{} missing ip or port setting' % (side,))

    try:
        ipaddress.ip_address(ip)
    except Exception:
        raise RuntimeError('{} ip address is not correct, value we get is: {}' % (side, ip))
    