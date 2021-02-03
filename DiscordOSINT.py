import requests
import base64
import json

from requests.exceptions import HTTPError

class DiscordOSINT:
    def __init__(self, email, password):
        self.base_url = "https://discord.com/api/v8"
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:85.0) Gecko/20100101 Firefox/85.0"
        
        self.fingerprint = None
        self.super_properties = None
        self.token = None

        self.friends = None
        self.guilds = None

        self.__get_token(email, password)


    def __get_fingerprint(self):
        # https://discord.com/api/v8/experiments give the X-Fingerprint if it doesn't exist in the headers of the request
        try:
            res = requests.get(f"{self.base_url}/experiments", headers={'User-Agent': self.user_agent})
            res.raise_for_status()
        except HTTPError as e:
            print(f'An HTTP error occurred: {e}')
        except Exception as err:
            print(f'An error occurred: {e}')
        else:
            self.fingerprint = res.json().get('fingerprint')
            return self.fingerprint

    
    def __get_super_properties(self):
        # Create X-Super-Properties
        super_properties = {
            "os": "Windows",
            "browser": "Firefox",
            "browser_user_agent": self.user_agent,
            "browser_version": 85.0,
            "os_version": 10.0,
            "release_channel": "stable",
            "client_build_number": 75603,
            "client_event_source": None,
            "referrer": "",
            "referring_domain": "",
            "referring_domain_current": ""
        }
    
        b64_sp = base64.b64encode((str(super_properties).encode()))
        self.super_properties = b64_sp.decode()
        return self.super_properties


    def __get_token(self, email, password):
        # Connect to discord to get the authorization token
        self.__get_fingerprint()
        self.__get_super_properties()

        payload = {"login": email,
                    "password": password,
                    "undelete": "false",
                    "captcha_key": None,
                    "login_source": None,
                    "gift_code_sku_id":None}

        headers = {"User-Agent": self.user_agent,
                   "Content-Type": "application/json",
                   "X-Fingerprint": self.fingerprint,
                   "X-Super-Properties": self.super_properties}

        try:
            res = requests.post(f"{self.base_url}/auth/login", headers=headers, json=payload)
            res.raise_for_status()
        except HTTPError as e:
            print(f'An HTTP error occurred: {e}')
        except Exception as err:
            print(f'An error occurred: {e}')
        else:
            self.token = res.json().get("token")
            return self.token

    
    def get_friends(self):
        headers = {"User-Agent": self.user_agent, "Authorization": self.token, "X-Super-Properties": self.super_properties}

        try:
            res = requests.get(f"{self.base_url}/users/@me/relationships", headers=headers)
            res.raise_for_status()
        except HTTPError as e:
            print(f'An HTTP error occurred: {e}')
        except Exception as err:
            print(f'An error occurred: {e}')
        else:
            self.friends = json.loads(res.text)
            return self.friends
            

    def get_guilds(self):
        headers = {"User-Agent": self.user_agent, "Authorization": self.token, "X-Super-Properties": self.super_properties}

        try:
            res = requests.get(f"{self.base_url}/users/@me/guilds", headers=headers)
            res.raise_for_status()
        except HTTPError as e:
            print(f'An HTTP error occurred: {e}')
        except Exception as err:
            print(f'An error occurred: {e}')
        else:
            self.guilds = json.loads(res.text)
            return self.guilds

