# theNextMessenger

[udp]
klient wysyła zapytanie o istnienie sewera [server discovery] na które serwer odpowiada swoim adressem (multicast)


[tcp]
klient łączy sie z serwerem gdzie następuje login/rejestracja
klient wybiera użytkownika danego użytkownika
serwer odsyła wiadomości do klienta +5 z starych
klient może wysłać wiadomości do tego użytkownika

message format:
64b     timestamp
16B     sender
255B    message


Database:
users
    ID
    Username

messages(one per each user conversation)
    ID
    Timestamp
    SentByID
    Read?


format reklamowania multicastem:
    "theNextMessenger"[ipaddr]
    
