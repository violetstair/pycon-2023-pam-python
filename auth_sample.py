import json
import time
import sys

sys.path = [
    '',
    '/usr/lib/python2.7',
    '/usr/lib/python2.7/plat-x86_64-linux-gnu',
    '/usr/lib/python2.7/lib-tk',
    '/usr/lib/python2.7/lib-old',
    '/usr/lib/python2.7/lib-dynload',
    '/usr/local/lib/python2.7/dist-packages',
    '/usr/lib/python2.7/dist-packages'
]

import requests
import jwt

client_id = 'google-auth-api-client-id'
client_secret = 'google-auth-client-secret'
slack_token = 'slack-bot-token'

scope = 'email'
device_code_url = 'https://oauth2.googleapis.com/device/code'
token_url = 'https://oauth2.googleapis.com/token'
slack_url = 'https://slack.com/api/chat.postMessage'

user_email = 'user@email'
slack_user_id = 'slack-user-id'
INTERVAL = 5


def _send_message(msg):
    data = {
        'token': slack_token,
        'channel': slack_user_id, # DM
        'as_user': True,
        'text': msg
    }
    r = requests.post(url='https://slack.com/api/chat.postMessage',data=data)
    print(r.status_code)
    return True


def _validate_email(email):
    return user_email == email


def _get_verification_code():
    payload = {'client_id': client_id, 'scope': 'email' }
    response = requests.post('https://oauth2.googleapis.com/device/code', data=payload)
    response_data = json.loads(response.text)

    user_code = response_data['user_code']
    verification_url = response_data['verification_url']
    device_code = response_data['device_code']
    
    # send to slack
    _send_message('Please visit ' + verification_url + ' and enter this code : ' + user_code)

    return {
        'client_id': client_id,
        'client_secret': client_secret,
        'device_code': device_code,
        'grant_type': 'urn:ietf:params:oauth:grant-type:device_code'
    }


def pam_sm_authenticate(pamh, flags, argv):
    max_pollng = 300
    access_token = None
    
    try:
        payload = _get_verification_code()
    except Exception as e:
        return pamh.PAM_AUTH_ERR
    
    while access_token is None or max_pollng > 0:
        time.sleep(INTERVAL)
        
        # 인증 정보 확인
        response = requests.post('https://oauth2.googleapis.com/token', data=payload)
        if response.status_code == 200:
            # 인증이 완료되면 response data의 id_token에 jwt 수신
            # jwt를 decode 하여 profile 확인
            response_data = json.loads(response.text)
            profile = jwt.decode(response_data['id_token'], verify=False, algorithms=["RS256"])
            
            # profile의 email 확인
            if _validate_email(str(profile['email'])):
                return pamh.PAM_SUCCESS
            else:
                return pamh.PAM_PERM_DENIED
        
        # 인증이 완료되지 않았다면 428 수신
        elif response.status_code == 428:
            max_pollng -= INTERVAL
        else:
            break
    return pamh.PAM_AUTH_ERR


def pam_sm_open_session(pamh, flags, argv):
    return pamh.PAM_SUCCESS


def pam_sm_close_session(pamh, flags, argv):
    return pamh.PAM_SUCCESS


def pam_sm_setcred(pamh, flags, argv):
    return pamh.PAM_SUCCESS


def pam_sm_acct_mgmt(pamh, flags, argv):
    return pamh.PAM_SUCCESS


def pam_sm_chauthtok(pamh, flags, argv):
    return pamh.PAM_SUCCESS
