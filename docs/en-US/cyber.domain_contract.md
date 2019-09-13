# The cyber.domain Smart Contract

## Purpose of the cyber.domain smart contract development
The `cyber.domain` smart contract is designed to create and handle domain names, create or delete a link of domain names to accounts, change domain name owners, as well as to handle a purchase of domain names at auction.  

The `cyber.domain` contract includes:
* a part of actions used to purchase a domain name at auction, including [checkwin](#the-checkwin-action), [biddomain](#the-biddomain-action), [biddmrefund](#the-biddmrefund-action), [newdomain](#the-newdomain-action) and [declarenames](#the-declarenames-declaration);
* a part of internal domain actions, including [passdomain](#the-passdomain-declaration), [linkdomain](#the-linkdomain-declaration), [unlinkdomain](#the-unlinkdomain-declaration) and [newusername](#the-newusername-declaration). Although a code of these actions is in the blockchain core, they are called up via smart contract;
* a list of domain names used in transactions.


## Requirements for domain names
Domain names in CyberWay are formed in accordance with rules and procedures of the Domain Name System (DNS). The following requirements are imposed on the structure of domain names:
  * a total number of characters in domain name should not exceed 253 pcs;
  * a domain name consists of individual parts, separated by the symbol «dot»;
  * the «dot» characters should not stand side by side in any domain name;
  * a number of characters in a separate part of domain name should not exceed 63 pcs;
  * the valid characters in the domain name are alphanumeric, plus «hyphen»;
  * the capital letters in the domain name are unacceptable;
  * a symbol «hyphen» should not be at the beginning or end of any domain name part;
  * the further right part of domain name must contain at least one alphabetic character. A presence of numeric characters only is not allowed.


## Domain name auction in the smart contract
The actions `checkwin`, `biddomain`, `biddmrefund` and `newdomain` are used to purchase a domain name at auction. The procedure for buying a domain name at the auction is the same as the procedure of buying an account name. The following rules apply to the procedure:  
* the bids for the purchase of any domain name are accepted at auction at any time;  
* the largest bid is used to determine only one domain name that can be purchased at the moment;
* a domain name is considered to be purchased at auction if the following conditions are met:
    * no more than a day is passed after betting on the current domain name;
    * at least one day has passed since previous redemption of any domain name;
* the number of domain names purchased at auction during a day should be no more than one;
* upon completion of auction, a token transfer of the winner is not returned. The winner can take advantage of the following opportunities:
    * to create her/his own domain name using the operation `newdomain` and become its owner;
    * to create subdomain names from it by adding the «dot» symbol and а name to the domain name on the left (for example, an owner of the domain `golos.io` can create subdomains such as `api.golos.io`, `ws.golos.io` and etc). It should be noted, that in `cyberway` the account names are formed by the same way — by adding parts to the left of word (for example, the names `msig.cyber`, `domain.cyber` can be formed from `cyber`). In this case the only direct inheritance of domain names is allowed. It means that if the owner has created a domain for the second level, a domain for the third level can’t be created (for example, the name `a.msig.cyber` can’t be formed from `cyber`).


> **Note:**  
>  The actions of the `cyber.domain` smart contract were originally intended for the distribution of domain names at auction. Later to this group of actions were added other actions, including such as creating a domain, transferring a domain, linking (or unlinking) a domain, declaring names used in transactions and creating a user name.  

### The checkwin action 
The `checkwin` action is used to register a domain name owner (a winner) at auction. This action does not require a special call and is called automatically with a certain periodic.  

The `checkwin` action has the following form:  
```cpp
[[eosio::action]] void checkwin();  
```
This action has no input parameters. One has to have `cyber.domain` smart contract rights to call this action.  

### The biddomain action
The `biddomain` action allows an account to bid at the auction. The action has the following form:  
```cpp
[[eosio::action]] void biddomain(
    name bidder,
    domain_name name,
    asset bid
);  
```
Parameters:  
`bidder` — an account name which bids at the action;  
`name` — a domain name (a string value in accordance with the requirements) on which the bid is done;  
`bid` — a structure value that specifies the bid.  
  
To perform this action the `cyber.domain` smart contract account should have the rights of the `bidder` account. If a bid with a bigger value appears at the auction, the bid with a smaller value is returned to the `bidder` account. The refunds are made automatically by internal calling `biddmrefund` from `biddomain`.   

### The biddmrefund action
The action `biddmrefund` is used to return a bid which was made at the auction to purchase a domain name if a higher bid is made for the same domain name. The action has the following form:  
```cpp
[[eosio::action]] void biddmrefund(
    name bidder,
    domain_name name
);  
```
Parameters:  
`bidder` —  the account name to which the funds are returned from the auction;   
`name` — the domain name for which the bid was made.  

In case of exceptional situations (a network failure or an error in the node's operation), the `biddmrefund` action can be called apart from calling `biddomain` (non-standard calling `biddmrefund`).

### The newdomain action 
The `newdomain` action is used to create a new domain name. The action has the following form:  
```cpp
[[eosio::action]] void newdomain(
    eosio::name creator,
    domain_name name
);
```
Parameters:  
`creator` — account name that creates a domain name;  
`name` — domain name being created.  

The `newdomain` action can be used:  
  * to create domain name by the system account `cyber.domain`;  
  * to create domain name by a winner of the domain name auction;  
  * to create a sub-domain name by the owner of a direct parent domain.  

The smart contract account `cyber.domain` must be privileged or have a permission to transfer funds from `cyber.namesaccount` (in case of a refund). Upon completion of this action, the `creator` account becomes the owner of the created domain name.

## Declarations of the names used in transactions  
It is not enough for one domain name to define a user name. The matter is, the user name is linked to both the owner account and the domain account (usually, it is a smart contract) and has a structure of the form `name@domain`. The domain part defines a scope for the `name`. The accounts with the same name can exist in different scopes. There are several variants that support `username` data and allow a textual representation of a user name to match an account name.  

**Restrictions imposed on a user name value**  
 The following requirements are imposed on a user name structure:  
  * a total number of characters in a user name should not exceed 32 pcs;  
  * a user name can consist of individual parts separated by the symbol «dot»;  
  * two «dot» symbols near each other are not allowed;  
  * the valid characters in a user name should be alphanumeric, a symbol «hyphen» could be used as well;  
  * the capital letters in a user name are unacceptable;  
  * a symbol «hyphen» should not be at the beginning or end of any user name part.  

### The declarenames declaration
The `declarenames` declaration is used to submit a list of structures with information about the domain names (or user names) used in transactions and their respective accounts. The declaration has the following form:  
```cpp
[[eosio::action]] void declarenames(
    vector<name_info> domains
);
```
Parameter:  
`domains` — an array of descriptions, each description of which is a structure in form of `name_info`.  

The `declarenames` declaration can be created by any account.   

### The newusername declaration
The `newusername` declaration is used to create a user name. When creating the user name, three fields are used — `creator`, `owner`, `name`. The `newusername` declaration has the following form:  
```cpp
[[eosio::action]] void newusername(
    name creator,
    name owner,
    username name
); 
```
Parameters:  
`creator` — an account name in scope of which the user name is created;  
`owner`— an account name that is the domain name owner;  
`name` —a string representation of the user name to be created.  

The lists of structures with information about the names used and the corresponding accounts are passed to the `newusername` declaration. The `newusername` declaration can be created by any account.  

The transaction requires a signature from the account `creator`.

### The passdomain declaration
The `passdomain` declaration is used to transfer a domain name from one account to another one (to change the domain name owner). The `passdomain` declaration has the following form:  
```cpp
[[eosio::action]] void passdomain(
    name from,
    name to,
    domain_name name
); 
```
Parameters:  
`from` — an account name from which a domain name is transferred and which owns it;  
`to` — an account name to which the domain name is transferred and which will be a new domain name owner;  
`name` — a string representation of the domain name to be transferred.  

The transaction requires a signature from the account `from` that is the domain name owner.  


### The linkdomain declaration 
The `linkdomain` declaration  is used to link a domain name to account name. The `linkdomain` declaration has the following form:  

```cpp
[[eosio::action]] void linkdomain(
    name owner,
    name to,
    domain_name name
);
```  
Parameters:  
`owner` — an account name that was a domain name owner;  
`to` — an account name that becomes new a domain name owner;  
`name` — a string representation of the domain name to be linked.  

### The unlinkdomain declaration
The `unlinkdomain` declaration is used to remove domain name link from account name (unlinking a domain name from the account name). The `unlinkdomain` declaration has the following form:  
```cpp
[[eosio::action]] void unlinkdomain(
    name owner,
    domain_name name
);
```  
Parameters:  
`owner` — an account name that was domain name owner (the domain name link is removed from the account name);  
`name` — a string representation of the domain name to be unlinked.  
 
**An example of using the declaration linkdomain and unlinkdomain**   
Let account to have a contract and be assigned a hard-to-remembered name `ajhgsd23qw`. To eliminate this drawback, this account uses `linkdomain` to link the domain name `helloworld` to its contract. It is easier for users to remember such domain as `@helloworld` and send transfers to this name. In contrast to sending transfers to the account name `ajhgsd23qw` the domain name `@helloworld` will be converted to `ajhgsd23qw` and the `declarenames` action will be added to the transaction indicating the used domain names.  
  
To stop using the domain name `@helloworld` the account has to call the `unlinkdomain` action. After that, the domain name `@helloworld` will not be converted to `ajhgsd23qw` and sending a transfer to it will be impossible.  
 
The `ajhgsd23qw` account in its environment can also create a user name for itself, for example,` admin`. In this case, the name `admin@@helloworld` will be converted to the name` ajhgsd23qw`. When adding a domain name, it is possible to use `admin@helloworld`.
 
### The name_info struct declaration
The `name_info` structure is used to check the presence of all elements at the time of executing the procedure, as well as the existence of linking a domain name with the specified account. The `name_info` structure declaration has the following form:  

```cpp
struct name_info {
    domain_name domain;
    name account;
    vector<username> users;
};
```  
Parameters:   
`domain` — a domain name;  
`account` — an account name matching to the domain name;  
`users` — a list of domain name users.  
 
The input to the `declarenames` declaration is an array of structures. A number of accepted structures should not be equal to zero. An error occurs when attempting to send an empty array.  
 
There are no matches for user names because a user name, unlike domain name, does not change its account for the entire time.  

The following additional restrictions are introduced:  
  * the structures must be sorted by domain name, that is, domain names must be arranged in ascending order. The exception is for a domain name that is an empty string. This is possible when the user name is not specified by the domain name, but explicitly in the smart contract. In this case, sorting should be done performed by account name — by field `.account`;  
  * domain name must not contain two identical values ​​`.domain`, except for empty values ​​(“ ”);  
  * the field `.account` in the domain name must not contain an empty value.  
 
### Notes  
  * Along with `declarenames` for internal use, there may be short account names as well. Such short names are replaced with the real account names. The conversion of internal short names to real account names is performed at the explorer level.   
  * This implementation does not verify that the accounts specified in `declarenames` exist in other actions. The implementation of validation is difficult because the actual validation process requires a lot of resources to read the ABI file format and deserialize the action. A lack of such control causes a certain risk. That is a sender may add more information to the transaction, so the superfluous part of it will not be checked. As a result, it will have to pay extra for overused `bandwidth` resources.  
  * This implementation does not contain information about positions of the used domain or user names. A transaction may contain an action with several account names as arguments, for example, `someaction(name 1, name 2, name 3, name 4, name 5)`. If user sends an action like `someaction(acc1, one@golos, two@golos, acc1, three@golos)` and it converts to (`someaction(acc1, acc1, acc1, acc1, acc3)` ), then `declarenames` will contain only used user names or domain names. At the same time, it is impossible to determine the positions where user names were used, for example:  
```
        declarenames([{
            domain:"golos",
            account:N(acc1),
            users:["one","two","three"]
        }])
```
  * Implemented support for the names like `username@@account` ( a presence of the symbols «@@» in the name means that the right side is not a domain, but the account name). For example, if a transaction converts view names `alice@@token`, `bob@@token`, `admin@@golos.io`, then the `declareames` declaration will contain the following arguments:
```
        declarenames([
            {domain:"", account:N(golos.io), users:["admin"]},
            {domain:"", account:N(token), users:["alice","bob"]}
        ])
```  
## Long domain names
When an account is created it is assigned a base32-encoded 8-byte identification name, which is a 12.5-character string. 60 bits are allocated for 12 characters. The remaining 4 bits are reserved for an additional symbol from the set {1,2,3,4, a, b, c, d, e, f, g, h, i, j}.  

A user can also assign her/his domain name to an account. The length of each part of the domain name should not exceed 63 characters. The number of domain names assigned to an account can be more than one. Since a fee is charged for storing a domain name, the number of domain names is limited and depends on the user funds.  
 
A domain name can be purchased at auction, and can also be created by the lower-level domain owner.  
  
Adding a domain name to an account allows a user to form domain transactions, the transactions with a link to the domain. Such transaction specify smart contract to be called and operations it performs. Domain name is not an identifier and can be transferred from one account to another.  

****
