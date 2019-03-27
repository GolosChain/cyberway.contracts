﻿# Смарт-контракт cyber.token

## Назначение cyber.token  
Системный смарт-контракт `cyber.token` предоставляет функции по управлению токенами, генерирует новые токены и хранит информацию о созданных токенах, предоставляет возможность проводить взаиморасчеты между аккаунтами.   

В состав смарт-контракта cyber.token входят следующие экшен-операции: `create`, `issue`, `retire`, `transfer`, `open`, `close`. 

## Экшен-операция create
Экшен-операция `create` используется для создания токена для обращения его в системе. Экшен-операция `create` имеет следующий вид:
```cpp
[[eosio::action]] void create(
    name   issuer,
    asset  maximum_supply
);
```
Параметры:  
`issuer` — имя аккаунта, создающего токен для обращения в системе;
`maximum_supply` — значение, содержащее поля:  
  * максимально возможное количество поставляемых токенов;  
  * символ токена (тип данных, однозначно определяющий токен):  
    * имя токена, состоящее из набора прописных букв;    
    * поле, задающее точность стоимости токена в виде количества знаков после запятой.  

Аккаунт `issuer` наделяется правами по выпуску и изъятию из обращения токенов. Права на выполнение экшен-операции `create` имеются только у смарт-контракта `token`. Для выполнения данной экшен-операции необходима подпись блок-продюсеров. За использование ресурсов `bandwidth` (RAM) плата взимается с аккаунта `issuer`.  

## Экшен-операция issue  
Экшен-операция `issue` используется для выпуска в обращение токена в системе.  
Экшен-операция `issue` имеет следующий вид:
```cpp
[[eosio::action]] void issue(
    name to,  
    asset quantity,  
    string memo
);
```
Параметры:  
`to` — имя аккаунта, на баланс которого поступает токен;  
`quantity` — значение, содержащее поля:   
  * количество выпущенных в обращение токенов;  
  * символ токена:
    * имя токена, состоящее из набора прописных букв;    
    * поле, задающее точность стоимости токена в виде количества знаков после запятой;  

`memo` — примечание, текст которого дополняет смысловое значение выпуска токена (например, эмиссия токена). Количество символов в строке не должно превышать 256 шт.  

При выполнении экшен-операции `create` в таблицу записывается символ токена и имя аккаунта `issuer`. При выполнении экшен-операции `issue` из полученного значения `quantity` берется символ токена и по нему, используя табличные данные, определяется аккаунт `issuer`. Правами на выполнение экшен-операции обладает аккаунт `issuer`. Количество выпущенных токенов не должно превышать значение `maximum_supply`, заданного в экшен-операции `create`. За использование ресурсов `bandwidth` (RAM) взимается плата c аккаунта `issuer`.

## Экшен-операция retire 
Экшен-операция `retire` используется для изъятия из обращения определенного количества токенов в системе. Экшен-операция `retire` имеет следующий вид:
```cpp
[[eosio::action]] void retire(
    asset quantity,
    string memo
);
```
Параметры:  
`quantity` — значение, содержащее поля:  
  * количество изымаемых из обращения токенов;  
  * символ токена:  
    * имя токена, состоящее из набора прописных букв;    
    * поле, задающее точность стоимости токена в виде количества знаков после запятой.  

Правами запуска экшен-операции обладает аккаунт `issuer`. За использование ресурсов `bandwidth` (RAM) плата взимается c аккаунта `issuer`. Указанное в экшен-операции количество изымаемых из обращения токенов также снимается с баланса аккаунта `issuer`, поэтому он не может изъять из обращения токенов больше, чем имеется  на его балансе.

## Экшен-операция transfer  
Экшен-операция `transfer` используется для передачи токена с баланса одного аккаунта на баланс другого. Экшен-операция `transfer` имеет следующий вид:  
```cpp
[[eosio::action]] void transfer(
    name from,
    name to,
    asset quantity,
    string  memo
);
```
Параметры:  
`from` — имя аккаунта-отправителя, с баланса которого снимаются токены;  
`to` — имя аккаунта-получателя, на баланс которого поступают токены;  
`quantity` — значение в виде структуры, задающее количество переводимых токенов. Количество токенов должно быть больше нуля;  
`memo` — примечание , уточняющее цель перевода токенов.   

Экшен-операция выполняется с отправкой уведомления на смарт-контракты отправителя и получателя токенов. Операция отправки уведомления имеет вид аналогичный экшен-операции `transfer`. Отличие состоит в том, что операция отправки уведомления выполняется не на смарт-контракте `cyber.token`, а на контрактах отправителя и получателя уведомления (например, если смарт-контракт `vesting` получает уведомление, он автоматически начисляет токены на баланс `vesting`). Для отправки токенов аккаунт должен быть наделен правами отправителя.  

За использование ресурсов `bandwidth` (RAM) плата взимается либо с аккаунта-отправителя, либо с аккаунта-получателя в зависимости от того, кто подписал транзакцию. В случае, если предварительно была выполнена экшен-операция `open`, никто из них не оплачивает `bandwidth`, так как используется уже созданная в БД запись.   

**Примечание**  
Раньше в EOS при пересылке токенов создавалась запись в БД для хранения баланса пользователя для случая, когда у получателя не было в наличии токена. Если аккаунт-отправитель оплачивал используемые ресурсы (RAM) за аккаунта-получателя, то существовала возможность расхода всей выделенной доли памяти аккаунту-получателю.  
С целью недопущения подобных случаев при выполнении экшен-операции `transfer` было принято решение ввести дополнительные экшен-операции `open` и `close`. Функциональное назначение данных операций — предварительное создание записи в БД, чтобы запись создавалась не во время выполнения экшен-операции `transfer`, а также ее удаление.  

## Экшен-операция open  
Экшен-операция `open` используется для создания записи в БД с указанием имени аккаунта, который должен оплатить используемую память, а также с указанием символа, для которого создается запись. Экшен-операция `open` имеет следующий вид:
```cpp
[[eosio::action]] void open(
    name owner,
    symbol symbol,
    name ram_payer
);
```
Параметры:  
`owner` — имя аккаунта, которому выделяется память;  
`symbol` — символ, для которого создается запись;  
`ram_payer` — имя аккаунта, который оплачивает используемую память;  

Выполнение экшен-операции `open` требует подписи аккаунта `ram_payer`.  

## Экшен-операция close  
Экшен-операция `close` является обратным действием по отношению к `open` и  используется для освобождение выделенной памяти в БД. Для выполнения данной экшен-операции требуется наличие нулевого баланса токена (определяемого символом) у аккаунта. Экшен-операция `close` имеет следующий вид:
```cpp
[[eosio::action]] void close(
    name owner,
    symbol symbol
);
```
Параметры:  
`owner` — имя аккаунта, которому была выделена память;  
`symbol` — символ, для которого удаляется запись.  

###Получение статистической информации по системным токенам
Для получения статистической информации по токенам в смарт-контракте `cyber.token` используются две таблицы `currency_stats` и `account`.  

Таблица `currency_stats` имеет следующий вид:  
```cpp
struct [[eosio::table]] currency_stats {
    asset supply;
    asset max_supply;
    name issuer;
};
```
Параметры:  
`supply` — значение в виде структуры с полями, показывающее количество токенов в обращении определенного вида;  
`max_supply` — значение в виде структуры с полями, показывающее максимально возможное количество в обращении токенов определенного вида;  
`issuer` — имя аккаунта, выпустившего токены.  

Первичным ключом для таблицы `currency_stats` является символьное значение в `asset`, по которому определяется токен. По токену определяется значение `supply` —  количество выпущенных в обращение токенов, а также имя аккаунта, выпустившего токены.  

Таблица `account` имеет следующий вид:  
```cpp
struct [[eosio::table]] account {
    asset balance;
};
```
Область видимости таблицы определяется именем аккаунта.  
Первичным ключом для таблицы `currency_stats` является символьное значение в `asset`, по которому определяется токен и его баланс для данного аккаунта.  