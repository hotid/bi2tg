Bi2tg
===========

Ugly-coded python daemon that sends Blue Iris alert videos to Telegram 

#Instructions:
```shell script
cd /opt
git clone https://github.com/hotid/bi2tg
cd bi2tg
virtualenv -p python3 .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Configuration:
```
/etc/bi2tg/settings.ini:

[bi5]
host = blue_iris_host
login = 
password = 

[tg]
token = BOT_TOKEN
chat_id = TG_CHAT_ID
```



Based on 