# -*- coding: utf-8 -*-
import requests

cti_url = "https://opencti.url:443"
cti_token = "token"
cti_headers = {'Authorization': f'Bearer {cti_token}',
           'Content-Type': 'application/json'}
cti_request_url = f'{cti_url}/graphql'


def form_cti_request() -> str:
    graphql_request = f"""
    query GetYara {{
        indicators(filters: {{key: pattern_type, values:"yara"}}) {{
            edges {{
                node {{
                    pattern
                }}
            }}
        }}
    }}
    """

    payload = {
        'query': graphql_request
    }
    return payload


def send_cti_request() -> str:
    master_yara = ""
    try:
        cti_payload = form_cti_request()
        cti_response = requests.post(cti_request_url, json=cti_payload, headers=cti_headers, verify=False)
        cti_response.raise_for_status()
        cti_data = cti_response.json()
        for e in cti_data['data']['indicators']['edges']:
            master_yara += e['node']['pattern']
        return (master_yara)
    except Exception as e:
        print(e)


def main():
    master_yara = send_cti_request()
    print(master_yara)
    with open('./master.yara', 'w') as f:
        f.write(master_yara)


if __name__ == "__main__":
    main()
