def get_gmail_service():
    creds = None
    token_path = 'token.json'
    credentials_path = 'creds.json'

    if os.path.exists(token_path):
        creds = Credentials.from_authorized_user_file(token_path, SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(credentials_path, SCOPES)
            auth_url, _ = flow.authorization_url(prompt='consent')
            print(f"\n🔗 Visit this URL in your browser:\n{auth_url}")
            code = input("📥 Paste the authorization code here: ")
            flow.fetch_token(code=code)
            creds = flow.credentials

        with open(token_path, 'w') as token:
            token.write(creds.to_json())

    return build('gmail', 'v1', credentials=creds)
