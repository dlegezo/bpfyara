# -*- coding: utf-8 -*-
import requests

cti_url = "https://open-cti...:443"
cti_token = "..."
cti_headers = {'Authorization': f'Bearer {cti_token}',
           'Content-Type': 'application/json'}
cti_request_url = f'{cti_url}/graphql'


def form_cti_request(requested_key: str, requested_value: str) -> str:
    graphql_request = f"""
    query GetIPObservable {{
      stixCyberObservables (filters: {{key: {requested_key}, values: "{requested_value}"}}){{
        edges {{
          node {{
            id
            entity_type
            observable_value
            objectMarking {{
              edges {{
                node {{
                  definition
                }}
              }}
            }}
          }}
        }}
      }}
    }}
    """
    payload = {
        'query': graphql_request
    }
    return payload


def send_cti_request(requested_key: str, requested_value: str) -> None:
    try:
        cti_payload = form_cti_request(requested_key, requested_value)
        cti_response = requests.post(cti_request_url, json=cti_payload, headers=cti_headers, verify=False)
        cti_response.raise_for_status()
        cti_data = cti_response.json()
        cti_observable_data = cti_data['data']['stixCyberObservables']['edges'][0]['node']
        print(f'Observable data: {cti_observable_data}')
    except Exception as e:
        print(e)


def main():
    # send_cti_request("hashes_SHA256", "c301eb35ea5e8c216aa841c96aca078f7fe9950382de17ae928d5de02b586033")
    send_cti_request("value", "starglowventures.com")


if __name__ == "__main__":
    main()
