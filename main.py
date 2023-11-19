from typing import Union, TypedDict
from requests import Session, Response
from requests.cookies import RequestsCookieJar


class User:
    __slots__ = 'login', 'password', 'app_id', 'app_secret', 'scope', 'cred'

    def __init__(self, *, login: str, password: str, app_id: int, app_secret: str = '', scope: Union[str, list[str]] = 'offline'):
        self.login = login
        self.password = password
        self.app_id = app_id
        self.app_secret = app_secret
        self.scope = scope
        self.cred = TypedDict('cred', {'access_token': dict, 'cookies': RequestsCookieJar})

    def auth(self):
        DirectAuth(self) if self.app_secret else ImplicitFlowAuth(self)


class ImplicitFlowAuth:
    def __init__(self, user: User):
        self.user = user
        self.session = Session()
        self.headers = {
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'accept-language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7'
        }
        self.setup = self.setup_()
        self.data = {
            'username': user.login,
            'password': user.password,
            'auth_token': self.setup.get('auth_token'),
            'sid': '',
            'uuid': '',
            'v': '5.207',
            'device_id': 'DKV2JR_qJKfST8MGzpK5M',
            'service_group': '',
            'agreement_hash': '',
            'oauth_force_hash': '1',
            'is_registration': '0',
            'oauth_response_type': 'token',
            'oauth_state': '',
            'oauth_scope': self.setup.get('scope'),
            'is_seamless_auth': '0',
            'to': 'aHR0cHM6Ly9vYXV0aC52ay5jb20vYmxhbmsuaHRtbA==',
            'version': '1',
            'app_id': user.app_id
        }
        self.cookies = RequestsCookieJar()
        self.errors = {'captcha': self.captcha, 'error': self.invalid_client, 'okay': lambda response: self.validate_phone(data.get('validate_info').get('sid')) if (data := response.json().get('data')).get('response_type') == 'need_2fa' else self.token(response)}
        self.connect_authorize()

    def setup_(self) -> TypedDict('setup', {'auth_token': str, 'anonymous_token': str, 'return_auth_hash': str, 'scope': str}):
        from re import findall
        url = f'https://oauth.vk.com/authorize?client_id={self.user.app_id}&redirect_uri=https://oauth.vk.com/blank.html&display=page&scope={self.user.scope}&response_type=token&revoke=1'
        response = self.session.get(url, headers=self.headers)
        self.cookies = response.cookies
        return {
            'auth_token':
                (a := findall(r'"access_token":"(.+)","anonymous_token":"(.+)","host_app_id".+"response_type":"token","scope":(\d+)',response.text)[0])[0],
            'anonymous_token':
                a[1],
            'return_auth_hash':
                findall(r'return_auth_hash=([a-zA-Z0-9]+)&\w+=', response.url)[0],
            'scope':
                a[2]
        }

    def connect_authorize(self, code: int = 0):
        url = 'https://login.vk.com/?act=connect_authorize'
        if code:
            self.data['code_2fa'] = code
            response = self.session.post(url, data=self.data, headers=self.headers, cookies=self.cookies)
            if response.json().get('type') == 'error':
                self.connect_authorize(int(input('code_2fa: ')))
            else:
                self.connect_authorize(int(input('code_2fa: '))) if response.json().get('access_token', {'type': 'okay'}).get('type') == 'error' else self.token(response)
        else:
            self.headers['origin'] = 'https://id.vk.com'
            response = self.session.post(url, data=self.data, headers=self.headers, cookies=self.cookies)
            self.errors.get(response.json().get('type'))(response)

    def token(self, response: Response):
        self.cookies.update(response.cookies)
        self.user.cred = {'access_token': response.json(), 'cookies': self.cookies}

    def validate_phone(self, sid: str):
        url = f'https://api.vk.com/method/auth.validatePhone?v=5.207&client_id={self.user.app_id}'
        data = {
            'device_id': 'DKV2JR_qJKfST8MGzpK5M',
            'external_device_id': '',
            'service_group': '',
            'lang': 'ru',
            'phone': '',
            'auth_token': self.setup.get('auth_token'),
            'sid': sid,
            'allow_callreset': '1',
            'supported_ways': 'push,email,passkey',
            'super_app_token': '',
            'access_token': ''
        }
        response = self.session.post(url, data=data, cookies=self.cookies)
        self.cookies.update(response.cookies)
        self.connect_authorize(int(input('code_2fa: ')))

    def invalid_client(self, _: Response):
        self.data['username'] = input('login: ')
        self.data['password'] = input('password: ')
        self.connect_authorize()

    def captcha(self, response: Response):
        self.data['captcha_sid'] = response.json().get('captcha_sid')
        print(response.json().get('captcha_img'))
        self.data['captcha_key'] = input('enter captcha key: ')
        self.connect_authorize()


class DirectAuth:
    def __init__(self, user: User):
        self.user = user
        self.session = Session()
        self.url = 'https://oauth.vk.com/token'
        self.params = {
            'grant_type': 'password',
            'client_id': user.app_id,
            'client_secret': user.app_secret,
            'username': user.login,
            'password': user.password,
            'scope': user.scope,
            'v': '5.131',
            '2fa_supported': '1'
        }
        self.headers = {
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'accept-language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7'
        }
        self.cookies = RequestsCookieJar()
        self.errors = {'invalid_client': self.invalid_client, 'need_validation': self.validate_phone, 'need_captcha': self.captcha, 'access_token': self.token}
        self.connect_authorize()

    def connect_authorize(self):
        response = self.session.get(self.url, params=self.params, headers=self.headers)
        self.errors.get(response.json().get('error', 'access_token'))(response)

    def two_fa(self, code: int):
        self.params['code'] = code
        response = self.session.get(self.url, params=self.params, headers=self.headers, cookies=self.cookies)
        self.two_fa(int(input('code_2fa: '))) if response.json().get('error') is not None else self.token(response)

    def token(self, response: Response):
        self.cookies.update(response.cookies)
        self.user.cred = {'access_token': response.json(), 'cookies': self.cookies}

    def validate_phone(self, response: Response):
        self.cookies = response.cookies
        redirect = self.session.get(response.json().get('redirect_uri'), headers=self.headers, cookies=self.cookies)
        self.cookies.update(redirect.cookies)
        self.two_fa(int(input('code_2fa: ')))

    def invalid_client(self, response: Response):
        if response.json().get('error_type') == 'username_or_password_is_incorrect':
            self.params['username'] = input('login: ')
            self.params['password'] = input('password: ')
        else:
            self.params['client_secret'] = input('app_secret: ')
        self.connect_authorize()

    def captcha(self, response: Response):
        self.params['captcha_sid'] = response.json().get('captcha_sid')
        print(response.json().get('captcha_img'))
        self.params['captcha_key'] = input('enter captcha key: ')
        self.connect_authorize()
