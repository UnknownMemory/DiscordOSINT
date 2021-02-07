import requests
import json

from requests.exceptions import HTTPError


def req_json(url, headers):
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
    except HTTPError as e:
        print(f'An HTTP error occurred: {e}')
    except Exception as err:
        print(f'An error occurred: {e}')
    else:
        return json.loads(response.text)
