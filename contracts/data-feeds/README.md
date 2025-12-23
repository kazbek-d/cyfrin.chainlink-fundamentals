### Build a Token Shop with Price Feeds

###### Token Shop: Using Chainlink Data Feeds to calculate the price
In this lesson, we'll build a "TokenShop" smart contract that enables users to purchase tokens. 
It will use the ETH/USD price feed to calculate how many tokens to issue to a purchaser, based on the amount of ETH they pay.
Our shop will leverage Chainlink Data Feeds to establish accurate token pricing in USD.


#### When users send ETH to the contract, it will:

- Query the current ETH/USD exchange rate.

- Calculate the USD value of the sent ETH.

- Determine the appropriate amount of tokens to mint based on our fixed USD token price.

- Mint and transfer the calculated tokens directly to the buyer.

### Deployed Addresses
- Token Shop: 0xF3a2Fd486894F378a6f84CD70b53464Ff9c2EF21
- Minter: 0x1915B272B3Ce8982Ff99AE1E4efcD04b8c679CB1