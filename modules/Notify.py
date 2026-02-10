import requests

WEBHOOK_URL = "DISCORDWEBHOOK"

message_content = f"""


    """

def send_message(message, user=None):
    if user:
        data = {
            "content": f"<@{user}> {message}"
        }
    else: 
        data = {
            "content": f"{message}"
        }
    response = requests.post(WEBHOOK_URL, json=data)
    try:
        response.raise_for_status()
        return response.status_code
    except requests.exceptions.HTTPError as err:
        return err

# send_message("server down",1093465261627162664)

