// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @title Vault
/// @notice INTENTIONALLY VULNERABLE example target for kai-security demos.
///         Do NOT deploy. The bugs below are planted so `kai audit` has
///         something real to find on a tiny, self-contained codebase.
contract Vault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    /// BUG 1 — reentrancy: the ETH is sent *before* the balance is zeroed,
    /// and there is no reentrancy guard, so a malicious receiver can re-enter
    /// withdraw() and drain the contract.
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] -= amount;
    }

    /// BUG 2 — unchecked return value: ERC-20 transfer() can return false
    /// instead of reverting; ignoring it lets a failed transfer look like a
    /// success.
    function sweepToken(IERC20 token, address to, uint256 amount) external {
        token.transfer(to, amount);
    }
}
