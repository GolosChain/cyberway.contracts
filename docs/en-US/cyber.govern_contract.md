# Govern Smart Contract

## Purpose of the cyber.govern smart contract development
 
The `cyber.govern` system smart contract contains the logic for selecting active validators and distributing remuneration for block production in accordance with the DPoS provisions.  
 
The cyber.govern smart contract includes the `onblock` action.
 
## onblock action

The `onblock` action is a system operation and is not accessible to an external user. It is called by the `cyber.bios` smart contract. The operation contains the logic of block production, including the logic of token issuance and the appointment of validators. This action has the following form:
```
[[eosio::action]] void onblock(name producer);
```
`producer` parameter is the name of the validator that succeed producing the next block.  

The `cyber.bios` smart contract activates the `onblock` action after each block produced by validators. Calling `onblock` requires the authorization of the `cyber.govern` smart contract account.  

## Main regulations concerning the validators

### Validator status

  * The status of a validator candidate can be obtained by any user who has signed up, switched to a zero proxy level and has his own stake in the amount of at least 50,000 CYBER as well as a server (node) that meets the requirements specified in [manual](https://cyberway.gitbook.io/en/validators/quick_reference).
  * The validators are selected from the candidates by users via voting (read more about [voting process](https://cyberway.gitbook.io/en/validators/voting_for_validators)).
  * The validators are divided into two groups according to the voting results — the main validators who received the biggest number of votes and reserved candidates.
  
### Active validators

  * Block production-wise, a schedule of active validators is automatically compiled, which includes all the main validators and one reserve candidate.
  * The selection of a reserve candidate for the schedule of active validators takes place according to the following rules. The priority of the candidate is calculated in accordance with the established formula, taking into account the number of votes cast for him and the time interval since his last appearance in the schedule of active validators.
  * Active validators produce blocks alternately according to the schedule.
  * The schedule of active validators is updated periodically every 4×A blocks, where A is the current number of active validators.
  * The number of active validators changes upwards from 21 to 101 inclusive. 
  * The number of active validators increases by one if two conditions are met:
    * at least 14 days have passed since the last increase in the number of active validators;
    * the number of votes cast for the main validators was less than 90 % of the total number of votes cast for all candidates.  


### Validator rewards

  * The validator is rewarded for blocks produced by him in accordance with the provisions of DPoS and taking into account the annual issue of tokens. Funds generated from the annual issue of tokens are distributed in the following fractions:
    * 10 % goes to reward pool for validators for block production;
    * 20 % goes to reward pool for workers;
    * 70 % goes to the stake pool that is distributed between validators and users that voted for them.  

  * Validator rewards are distributed in the following proportions:  
    * 10 % from the validators pool goes to a validator, as well as commissions that he/she sets, which are taken from the stake pool;  
    * the rest of the stake pool is distributed between the proxy and generic accounts that voted for this specific validator.  
