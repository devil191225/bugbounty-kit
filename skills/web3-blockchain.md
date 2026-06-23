# Web3 / Smart Contract Security — Vulnerability Reference
> Source: SigP Solidity Security Blog, Trail of Bits, OpenZeppelin, Immunefi | RAG Knowledge Base | Full detail preserved

---

## Overview — Why Smart Contract Bugs Are High Severity

- Code is immutable after deployment (no silent patches)
- Bugs directly control financial assets (ETH, ERC-20, NFTs)
- On-chain transactions are irreversible
- Open-source — attackers read the same code as auditors
- Bug bounties often pay 10x–100x web app equivalents (Immunefi, bug reports >$1M)

---

## 1. Reentrancy

### Classic Reentrancy (The DAO Attack)

**Root Cause:** Contract sends ETH before updating internal state, allowing attacker's fallback to re-enter and drain funds repeatedly.

**Vulnerable Contract:**
```solidity
contract EtherStore {
    mapping(address => uint256) public balances;

    function depositFunds() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdrawFunds(uint256 _weiToWithdraw) public {
        require(balances[msg.sender] >= _weiToWithdraw);
        // BUG: external call BEFORE state update
        require(msg.sender.call.value(_weiToWithdraw)());
        balances[msg.sender] -= _weiToWithdraw;  // too late
    }
}
```

**Attack Contract:**
```solidity
contract Attack {
    EtherStore public etherStore;
    uint256 public attackValue = 1 ether;

    constructor(address _etherStoreAddress) {
        etherStore = EtherStore(_etherStoreAddress);
    }

    function pwnEtherStore() public payable {
        require(msg.value >= attackValue);
        etherStore.depositFunds.value(attackValue)();
        etherStore.withdrawFunds(attackValue);
    }

    // Fallback called every time ETH is received
    function() payable {
        if (etherStore.balance > attackValue) {
            etherStore.withdrawFunds(attackValue);  // re-enters!
        }
    }
}
```

**Fix — Checks-Effects-Interactions Pattern:**
```solidity
function withdrawFunds(uint256 _weiToWithdraw) public {
    require(balances[msg.sender] >= _weiToWithdraw);
    balances[msg.sender] -= _weiToWithdraw;   // 1. Update state FIRST
    msg.sender.transfer(_weiToWithdraw);       // 2. THEN external call
}
```

**Fix — Mutex/ReentrancyGuard:**
```solidity
bool private locked;
modifier noReentrant() {
    require(!locked, "Reentrant call");
    locked = true;
    _;
    locked = false;
}

// OpenZeppelin ReentrancyGuard
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
contract Safe is ReentrancyGuard {
    function withdraw() external nonReentrant { ... }
}
```

**Real-World Impact:** The DAO hack (2016) — $60 million USD stolen.

### Cross-Function Reentrancy

```solidity
contract CrossFunctionRe {
    mapping(address => uint) public balances;

    function transfer(address to, uint amount) public {
        if (balances[msg.sender] >= amount) {
            balances[to] += amount;
            balances[msg.sender] -= amount;
        }
    }

    function withdraw() public {
        uint amount = balances[msg.sender];
        // BUG: call before update
        (bool success,) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] = 0;  // too late
    }
}
```

**Attack:** During `withdraw()` callback, call `transfer()` to move balance to another address before it's zeroed.

### Read-Only Reentrancy

Attacker exploits a view function that reads stale state during a reentrancy call. Example: Curve Finance reentrancy bug where price oracle could be manipulated during receive().

---

## 2. Integer Overflow and Underflow

**Pre-Solidity 0.8.0:** Arithmetic wraps silently around type bounds.
**Solidity 0.8.0+:** Arithmetic reverts on overflow/underflow by default.
**Fix for older code:** Use OpenZeppelin SafeMath library.

### Overflow — TimeLock Bypass

```solidity
contract TimeLock {
    mapping(address => uint) public balances;
    mapping(address => uint) public lockTime;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
        lockTime[msg.sender] = block.timestamp + 1 weeks;
    }

    function increaseLockTime(uint _secondsToIncrease) public {
        // BUG: can overflow to 0 (pre-0.8.0)
        lockTime[msg.sender] += _secondsToIncrease;
    }

    function withdraw() public {
        require(block.timestamp > lockTime[msg.sender]);
        uint transferValue = balances[msg.sender];
        balances[msg.sender] = 0;
        msg.sender.transfer(transferValue);
    }
}
```

**Attack:** Pass `type(uint256).max - lockTime[msg.sender] + 1` → lockTime overflows to 0 → withdraw immediately.

### Underflow — Unlimited Balance

```solidity
contract Token {
    mapping(address => uint) balances;
    uint public totalSupply;

    function transfer(address _to, uint _value) public returns (bool) {
        // BUG: uint underflow — if balance < value, result wraps to huge number
        require(balances[msg.sender] - _value >= 0);  // always true for uint!
        balances[msg.sender] -= _value;               // underflows
        balances[_to] += _value;
        return true;
    }
}
```

**Attack:** Call `transfer()` with `_value > balances[msg.sender]` → attacker gains 2^256 - delta balance.

**SafeMath (fix for pre-0.8.0):**
```solidity
library SafeMath {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        assert(c >= a);
        return c;
    }
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        assert(b <= a);
        return a - b;
    }
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) return 0;
        uint256 c = a * b;
        assert(c / a == b);
        return c;
    }
}
```

---

## 3. Access Control Vulnerabilities

### tx.origin Authentication (Phishing Attack)

```solidity
contract Wallet {
    address public owner;
    constructor() public { owner = tx.origin; }

    function withdraw() public {
        // BUG: tx.origin is original sender, not immediate caller
        require(tx.origin == owner);
        payable(msg.sender).transfer(address(this).balance);
    }
}
```

**Attack Contract:**
```solidity
contract PhishingAttack {
    Wallet wallet;
    constructor(address _walletAddress) { wallet = Wallet(_walletAddress); }

    // Trick wallet owner into calling this (e.g., "claim free tokens")
    function claimRewards() public {
        // tx.origin = victim (wallet owner)
        // msg.sender = this contract address
        wallet.withdraw();  // passes tx.origin == owner check!
    }
}
```

**Fix:** Always use `msg.sender` for authentication, never `tx.origin`.

### Unprotected Initialization

```solidity
// Vulnerable: any address can call initialize()
contract Proxy {
    address public implementation;
    address public admin;
    bool public initialized;

    // BUG: no access control on initialize
    function initialize(address _impl) public {
        require(!initialized);
        implementation = _impl;
        admin = msg.sender;
        initialized = true;
    }
}
```

**Attack:** Deploy proxy, immediately call `initialize()` before the legitimate deployer → attacker becomes admin.

### Unprotected selfdestruct

```solidity
function destroy() public {
    // BUG: no access control
    selfdestruct(payable(msg.sender));
}
```

**Attack:** Any address calls `destroy()` → contract eliminated, all ETH sent to attacker.

### Default Visibility (Public by Default, pre-0.5.0)

```solidity
contract HashForEther {
    function withdrawWinnings() {
        require(uint32(msg.sender) == 0);
        _sendWinnings();
    }

    // BUG: no visibility = public by default (pre-0.5.0)
    function _sendWinnings() {
        // Any address can call this directly!
        msg.sender.transfer(this.balance);
    }
}
```

---

## 4. Delegatecall to Untrusted Callee / Storage Collision

**Mechanism:** `delegatecall` executes callee's code in the **caller's storage context**. Storage slots align by position index, not by variable name.

**Vulnerable Pattern:**
```solidity
contract FibonacciLib {
    uint public start;                // slot 0
    uint public calculatedFibNumber;  // slot 1

    function setStart(uint _start) public {
        start = _start;  // writes to CALLER's slot 0
    }
}

contract FibonacciBalance {
    address public fibonacciLibrary;  // slot 0 ← SAME as FibonacciLib.start!
    uint public calculatedFibNumber;  // slot 1
    uint public start = 3;            // slot 2
    uint withdrawalCounter;           // slot 3

    fallback() external {
        require(fibonacciLibrary.delegatecall(msg.data));
    }
}
```

**Attack:**
1. Call fallback with `setStart(ATTACKER_CONTRACT_ADDRESS)` as calldata
2. `delegatecall` to `fibonacciLibrary.setStart()` writes to slot 0 = `fibonacciLibrary`
3. `fibonacciLibrary` now points to attacker contract
4. Next fallback call executes attacker's code

**Storage Collision in Proxy Patterns:**
If implementation uses slot 0 for `owner` but proxy also uses slot 0 for `admin`, they collide and overwrite each other.

**EIP-1967 Fix — Deterministic Storage Slots:**
```solidity
// Computed as keccak256("eip1967.proxy.implementation") - 1
bytes32 internal constant _IMPLEMENTATION_SLOT = 
    0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

// Computed as keccak256("eip1967.proxy.admin") - 1
bytes32 internal constant _ADMIN_SLOT = 
    0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;
```

---

## 5. Flash Loan Attacks

**Mechanism:** Borrow massive amounts of tokens in a single transaction (zero collateral required) as long as they're repaid with fee in the same transaction.

**Flash Loan Attack Flow:**
1. Borrow 10M USDC from Aave (no collateral — repay before TX ends)
2. Buy all of token X on Uniswap with 5M USDC → price spikes 10x
3. Deposit inflated token X as collateral on vulnerable protocol
4. Borrow against inflated collateral (massive over-borrow)
5. Repay original 10M USDC + 0.09% fee to Aave
6. Keep over-borrowed assets as profit

**Real-World Examples:**
- bZx (2020): $350,000 and $600,000 stolen via flash loan oracle manipulation
- Harvest Finance (2020): $34 million
- Pancake Bunny (2021): $45 million
- Cream Finance (2021): $130 million

**Root Cause:** Using spot prices as oracle instead of TWAP.

---

## 6. Price Oracle Manipulation

**Vulnerable Spot Price Oracle (manipulable in same block):**
```solidity
function getPrice(address token) public view returns (uint) {
    (uint reserve0, uint reserve1,) = uniswapPair.getReserves();
    return reserve1 * 1e18 / reserve0;  // BUG: instant spot price — manipulable via flash loan
}
```

**Correct Chainlink Oracle Usage:**
```solidity
function getLatestPrice() public view returns (int) {
    (
        uint80 roundID,
        int price,
        uint startedAt,
        uint timeStamp,
        uint80 answeredInRound
    ) = priceFeed.latestRoundData();

    require(timeStamp > 0, "Round not complete");
    require(block.timestamp - timeStamp < 3600, "Stale price — oracle may be down");
    require(answeredInRound >= roundID, "Stale price");
    require(price > 0, "Invalid negative price");

    return price;
}
```

**TWAP Oracle (Uniswap v3 — manipulation-resistant):**
```solidity
(int56[] memory tickCumulatives, ) = pool.observe([1800, 0]);  // 30-minute TWAP
int56 tickCumulativeDelta = tickCumulatives[1] - tickCumulatives[0];
int24 timeWeightedAverageTick = int24(tickCumulativeDelta / 1800);
uint256 price = TickMath.getSqrtRatioAtTick(timeWeightedAverageTick);
```

---

## 7. Signature Replay Attacks

**Vulnerable — No Nonce, No Chain ID:**
```solidity
contract Marketplace {
    function executeTrade(
        address seller, uint256 tokenId, uint256 price, bytes memory signature
    ) public {
        bytes32 messageHash = keccak256(abi.encodePacked(seller, tokenId, price));
        address recovered = recoverSigner(messageHash, signature);
        require(recovered == seller, "Invalid signature");
        // BUG: same signature can be replayed indefinitely on same or other chains!
        _executeTransfer(seller, msg.sender, tokenId, price);
    }
}
```

**Attack:** Valid signature captured from one transaction replayed in a second transaction for free.

**Fix — Include Nonce, Chain ID, Contract Address:**
```solidity
mapping(address => uint256) public nonces;

function executeTrade(
    address seller, uint256 tokenId, uint256 price,
    uint256 nonce, bytes memory signature
) public {
    require(nonces[seller] == nonce, "Invalid nonce");
    bytes32 messageHash = keccak256(abi.encodePacked(
        block.chainid,    // cross-chain replay protection
        address(this),    // cross-contract replay protection
        seller, tokenId, price, nonce
    ));
    bytes32 ethSignedMessage = keccak256(
        abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash)
    );
    address recovered = recoverSigner(ethSignedMessage, signature);
    require(recovered == seller, "Invalid signature");
    nonces[seller]++;
    _executeTransfer(seller, msg.sender, tokenId, price);
}
```

**EIP-712 (Structured Data Signing — best practice):**
```solidity
bytes32 public constant DOMAIN_SEPARATOR = keccak256(abi.encode(
    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
    keccak256(bytes("MyApp")),
    keccak256(bytes("1")),
    block.chainid,
    address(this)
));
```

---

## 8. Front-Running / MEV / Sandwich Attacks

### Commit-Reveal Front-Running

```solidity
contract FindThisHash {
    bytes32 constant public hash = 0xb5b5b97f7b9c...;
    function solve(string memory solution) public {
        require(keccak256(abi.encodePacked(solution)) == hash);
        payable(msg.sender).transfer(address(this).balance);
    }
}
```

**Attack:** Attacker sees `solve("Ethereum!")` in mempool → copies transaction with higher `gasPrice` → their transaction mined first → wins reward.

**ERC20 Approve Front-Running:**
- Alice: `approve(Bob, 100)` → then `approve(Bob, 50)` (reduce allowance)
- Bob front-runs the second TX: calls `transferFrom(Alice, Bob, 100)` before Alice's update
- Alice's `approve(Bob, 50)` confirms
- Bob calls `transferFrom(Alice, Bob, 50)` again → Bob received 150 total
- **Fix:** Use `increaseAllowance`/`decreaseAllowance` from OpenZeppelin ERC20

### Sandwich Attack on DEX

1. Attacker sees large swap (e.g., 1000 ETH for USDC) in mempool
2. **Front-run:** Buy USDC before victim (drives price up) with higher gas
3. Victim's TX executes at worse price (slippage)
4. **Back-run:** Sell USDC at inflated price for profit

**Defenses:**
- Slippage tolerance limits (low `minAmountOut`)
- Commit-reveal schemes
- Private mempools (Flashbots Protect, MEV Blocker)
- `require(tx.gasprice <= maxGasPrice)` — rarely practical

---

## 9. Weak Randomness

**Insecure Entropy Sources:**
```solidity
// All of these are manipulable by miners/validators:
uint random1 = uint(block.timestamp) % 10;
uint random2 = uint(blockhash(block.number - 1)) % 10;
uint random3 = uint(keccak256(abi.encodePacked(block.difficulty, block.timestamp))) % 10;
uint random4 = uint(block.prevrandao) % 10;  // post-merge, but validator-influenced
```

**Vulnerability:** Miners (pre-merge) can withhold blocks to influence `blockhash`. `block.timestamp` is miner-controllable within ~15 seconds. Validators (post-merge) can influence `prevrandao` through lookahead.

**Commit-Reveal Scheme:**
```solidity
mapping(address => bytes32) public commitments;
mapping(address => bool) public revealed;

function commit(bytes32 _commitment) external {
    commitments[msg.sender] = _commitment;  // keccak256(abi.encodePacked(number, salt))
}

function reveal(uint _number, bytes32 _salt) external {
    require(!revealed[msg.sender]);
    require(keccak256(abi.encodePacked(_number, _salt)) == commitments[msg.sender]);
    revealed[msg.sender] = true;
    // Use combination of all participants' committed numbers
}
```

**Best Practice:** Use **Chainlink VRF** (Verifiable Random Function) — cryptographically provable randomness from off-chain oracle.

---

## 10. Proxy Upgrade Pattern Vulnerabilities

### Uninitialized Implementation Contract

```solidity
contract Implementation {
    address public owner;
    bool public initialized;

    function initialize(address _owner) public {
        require(!initialized, "Already initialized");
        owner = _owner;
        initialized = true;
    }

    function destroy() public {
        require(msg.sender == owner);
        selfdestruct(payable(owner));  // CRITICAL: can destroy all proxies
    }
}
```

**Attack:**
1. Attacker calls `initialize()` directly on implementation contract (not via proxy)
2. Sets themselves as owner
3. Calls `destroy()` — all proxies pointing to this implementation are now bricked permanently

### Function Selector Clash

If implementation has same 4-byte selector as proxy admin function, non-admin calls may hit the wrong function.

```
keccak256("transfer(address,uint256)")[0:4] = a9059cbb
# If proxy admin function also hashes to a9059cbb, collision occurs
```

**OpenZeppelin Transparent Proxy:** Admin cannot call implementation functions; non-admin cannot call admin functions. Eliminates selector clash.

**UUPS (Universal Upgradeable Proxy Standard):**
- Upgrade logic in implementation (not proxy)
- `upgradeTo()` function must be access-controlled
- Smaller proxy bytecode — gas efficient

---

## 11. Token Vulnerabilities (ERC-20, ERC-721)

### ERC-20 Approve/TransferFrom Race Condition

See Section 8 above. Use `increaseAllowance`/`decreaseAllowance`.

### Deflationary Token Accounting (Fee-on-Transfer)

```solidity
// Bug: protocol assumes tokens arrive in full
function deposit(uint256 amount) external {
    token.transferFrom(msg.sender, address(this), amount);
    balances[msg.sender] += amount;  // BUG: if token has fee-on-transfer,
                                     // actual received < amount
}

// Fix: use actual received amount
uint256 before = token.balanceOf(address(this));
token.transferFrom(msg.sender, address(this), amount);
uint256 received = token.balanceOf(address(this)) - before;
balances[msg.sender] += received;  // correct
```

### ERC-721 safeTransfer Reentrancy

`safeTransferFrom` calls `onERC721Received` on the recipient → potential reentrancy if recipient is a contract.

---

## 12. Hidden Mint / Backdoor in Token Contracts

**Hidden Mint Function:**
```solidity
// "Renounced" owner can still mint via hidden function
function _m1nt(address to, uint256 amount) internal {
    _mint(to, amount);
}

// Callable via low-level call with obfuscated selector
function () external payable {
    if (msg.data.length >= 4 && bytes4(msg.data) == 0xdeadbeef) {
        _m1nt(msg.sender, 1000000 * 10**18);
    }
}
```

**Fake Renounce:**
```solidity
// Owner appears to be zero address but contract has hidden override
function renounceOwnership() public override onlyOwner {
    // Does NOT call super.renounceOwnership()
    emit OwnershipTransferred(owner(), address(0));
    // _owner is NOT actually set to address(0)
}
```

**Honeypot Token:**
```solidity
function transfer(address to, uint256 amount) public override returns (bool) {
    if (to != owner() && to != uniswapPair) {
        revert("Transfers disabled");  // can't sell!
    }
    return super.transfer(to, amount);
}
```

---

## Smart Contract Audit Checklist

### Reentrancy
- [ ] All external calls follow Checks-Effects-Interactions pattern
- [ ] ReentrancyGuard applied to critical functions
- [ ] Cross-function reentrancy paths considered

### Access Control
- [ ] All privileged functions have `onlyOwner`/role modifiers
- [ ] `tx.origin` never used for authentication
- [ ] `initialize()` functions protected against double initialization
- [ ] `selfdestruct` access controlled

### Math/Logic
- [ ] Solidity 0.8.0+ or SafeMath for all arithmetic
- [ ] No spot-price oracles for value calculations
- [ ] Slippage/deadline parameters on DEX interactions

### Signatures
- [ ] Nonces prevent replay attacks
- [ ] Chain ID included in signed data
- [ ] Contract address included in signed data
- [ ] EIP-712 structured signing used

### Proxies
- [ ] Implementation contract initialized at deploy
- [ ] EIP-1967 storage slots for proxy admin/implementation
- [ ] No function selector clashes
- [ ] UUPS upgrade function access controlled

### Randomness
- [ ] No `block.timestamp`, `blockhash`, `block.difficulty` as entropy
- [ ] Chainlink VRF used for on-chain randomness

---

## Web3 Bug Bounty Platforms

| Platform | Typical Payouts | Focus |
|---|---|---|
| Immunefi | $50K–$10M+ | Smart contracts, DeFi, bridges |
| HackerOne (Web3) | $10K–$500K | Crypto exchanges, wallets |
| Code4rena | Contest-based | Smart contract code competitions |
| Sherlock | Contest + perpetual | DeFi protocol audits |
| Cantina | Contest | Smart contract security |
| Hats Finance | On-chain bounties | Decentralized bug bounty |

**Severity Framework (Immunefi):**
- Critical: >$500K potential loss, private key loss, draining LP/treasury
- High: $100K–$500K potential loss, significant fund loss  
- Medium: $1K–$100K potential loss, loss of user funds below threshold
- Low: <$1K, minimal financial impact
