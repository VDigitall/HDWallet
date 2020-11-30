//
//  BitcoinAddress.swift
//  HDWalletKit
//
//  Created by Pavlo Boiko on 1/8/19.
//  Copyright © 2019 Essentia. All rights reserved.
//

import Foundation

public enum AddressType {
    case pubkeyHash
    case scriptHash
    case wif
	
	public func addressPrefix(for coin: Coin) -> UInt8 {
		switch self {
		case .pubkeyHash:
			return coin.publicKeyHash
		case .scriptHash:
			return coin.scriptHash
		case .wif:
			return coin.wifAddressPrefix
		}
	}
}

public protocol AddressProtocol {
    var coin: Coin { get }
    var type: AddressType { get }
    var data: Data { get }
    
    var base58: String { get }
    var cashaddr: String { get }
}

public typealias Address = AddressProtocol

public enum AddressError: Error {
    case invalid
    case invalidScheme
    case invalidVersionByte
}

public struct LegacyAddress: Address {
    public let coin: Coin
    public let type: AddressType
    public let data: Data
    public let base58: Base58Check
    public let cashaddr: String
    
    public typealias Base58Check = String
    
    public init(_ base58: Base58Check, coin: Coin) throws {
        guard let raw = Base58.decode(base58) else {
            throw AddressError.invalid
        }
        let checksum = raw.suffix(4)
        let pubKeyHash = raw.dropLast(4)
        let checksumConfirm = pubKeyHash.doubleSHA256.prefix(4)
        guard checksum == checksumConfirm else {
            throw AddressError.invalid
        }
        self.coin = coin
        
        let type: AddressType
        let addressPrefix = pubKeyHash[0]
        switch addressPrefix {
        case coin.publicKeyHash:
            type = .pubkeyHash
        case coin.wifAddressPrefix:
            type = .wif
        case coin.scriptHash:
            type = .scriptHash
        default:
            throw AddressError.invalidVersionByte
        }
        
        self.type = type
        self.data = pubKeyHash.dropFirst()
        self.base58 = base58
        
        // cashaddr
        switch type {
        case .pubkeyHash:
            let payload = Data([coin.publicKeyHash]) + self.data
            self.cashaddr = Bech32.encode(payload, prefix: coin.scheme)
        case .wif:
            let payload = Data([coin.wifAddressPrefix]) + self.data
            self.cashaddr = Bech32.encode(payload, prefix: coin.scheme)
        default:
            self.cashaddr = ""
        }
    }
	
	/// Initialize Legacy bitcoin address
	/// - Parameters:
	///   - hash: This can be `Script` or wallet public key hash (sha256)
	///   - coin: Target blockchain
	///   - addressType: Type of address: `pubkeyHash`, `scriptHash`, `wif`
	public init(hash: Data, coin: Coin, addressType: AddressType) {
		let ripemd160Hash = RIPEMD160.hash(hash)
		let addressPrefixByte = addressType.addressPrefix(for: coin)
		let entendedRipemd160Hash = Data([addressPrefixByte]) + ripemd160Hash
		let sha = entendedRipemd160Hash.doubleSHA256
		let checksum = sha[..<4]
		let ripemd160HashWithChecksum = entendedRipemd160Hash + checksum
		let base58 = Base58.encode(ripemd160HashWithChecksum)
		
		self.coin = coin
		self.type = addressType
		self.data = sha
		self.base58 = base58
		
		switch addressType {
		case .pubkeyHash:
			let payload = Data([coin.publicKeyHash]) + self.data
			self.cashaddr = Bech32.encode(payload, prefix: coin.scheme)
		case .wif:
			let payload = Data([coin.wifAddressPrefix]) + self.data
			self.cashaddr = Bech32.encode(payload, prefix: coin.scheme)
		default:
			self.cashaddr = ""
		}
	}
}
