from googleapiclient.discovery import build


def build_gmail_service(credentials):
    return build("gmail", "v1", credentials=credentials)


def get_message(service, message_id: str, user_id: str = "me", fmt: str = "full") -> dict:
    return service.users().messages().get(
        userId=user_id,
        id=message_id,
        format=fmt
    ).execute()
