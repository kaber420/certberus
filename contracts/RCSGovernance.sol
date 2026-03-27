// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title RCSGovernance
 * @dev Example contract for the Sovereign Trust Network (RCS) to vote on Intermediate CAs.
 */
contract RCSGovernance {
    struct IntermediateCA {
        string name;
        string nameConstraints; // e.g., "*.empresa.comu"
        address owner;
        bool approved;
        uint256 voteCount;
        bool exists;
    }

    address public rootAdmin;
    mapping(address => IntermediateCA) public intermediateCAs;
    mapping(address => mapping(address => bool)) public hasVoted; // voter => candidate
    address[] public voterRegistry; // In a real DAO, this would be token holders or reputable nodes

    event CARequested(address indexed caAddress, string name);
    event CAApproved(address indexed caAddress);
    event CARevoked(address indexed caAddress);

    constructor() {
        rootAdmin = msg.sender;
    }

    function requestAdmission(string memory _name, string memory _constraints) public {
        require(!intermediateCAs[msg.sender].exists, "Already requested or exists");
        intermediateCAs[msg.sender] = IntermediateCA(_name, _constraints, msg.sender, false, 0, true);
        emit CARequested(msg.sender, _name);
    }

    function vote(address _caAddress) public {
        // Simple logic: In a real scenario, check if msg.sender is a valid voter/token holder
        require(intermediateCAs[_caAddress].exists, "CA does not exist");
        require(!hasVoted[msg.sender][_caAddress], "Already voted");
        
        intermediateCAs[_caAddress].voteCount++;
        hasVoted[msg.sender][_caAddress] = true;

        // Threshold logic (e.g., 3 votes for this mockup)
        if (intermediateCAs[_caAddress].voteCount >= 3 && !intermediateCAs[_caAddress].approved) {
            intermediateCAs[_caAddress].approved = true;
            emit CAApproved(_caAddress);
        }
    }

    function revoke(address _caAddress) public {
        require(msg.sender == rootAdmin, "Only Root Admin can revoke for now"); // Or another DAO vote
        intermediateCAs[_caAddress].approved = false;
        emit CARevoked(_caAddress);
    }

    function isCAValid(address _caAddress) public view returns (bool) {
        return intermediateCAs[_caAddress].approved;
    }
}
