<img width="400" src="../docs/logo.jpg" />  

***  
[![GitHub](https://img.shields.io/github/license/cyberway/cyberway.contracts.svg)](https://github.com/cyberway/cyberway.contracts/blob/master/LICENSE)

# cyber.domain

The system smart contract `cyber.domain` is designed to create and handle domain names, create or delete a link of domain names to accounts, change domain name owners, as well as to handle a purchase of domain names at auction.  

The cyber.domain contract includes:
  * a part of actions used to purchase a domain name at auction, including checkwin, biddomain, biddmrefund, newdomain and declarenames;
  * a part of internal domain actions, including passdomain, linkdomain, unlinkdomain and newusername. Although a code of these actions is in the blockchain core, they are called up via smart contract;
  * a list of domain names used in transactions.  

More information about this contract can be found [here](https://cyberway.gitbook.io/en/devportal/system_contracts/cyber.domain_contract).
