//
//  PrivateKey.swift
//  HDWalletKit
//
//  Created by Pavlo Boiko on 10/4/18.
//  Copyright © 2018 Essentia. All rights reserved.
//

import Foundation
import secp256k1

enum PrivateKeyType {
    case hd
    case nonHd
}

public struct PrivateKey {
    public let raw: Data
    public let chainCode: Data
    public let index: UInt32
    public let coin: Coin
    private var keyType: PrivateKeyType
    
    public init(seed: Data, coin: Coin) {
        let output = Crypto.HMACSHA512(key: "Bitcoin seed".data(using: .ascii)!, data: seed)
        self.raw = output[0..<32]
        self.chainCode = output[32..<64]
        self.index = 0
        self.coin = coin
        self.keyType = .hd
    }
    
    public init?(pk: String, coin: Coin) {
        switch coin {
        case .ethereum:
            self.raw = Data(hex: pk)
        default:
            let utxoPkType = UtxoPrivateKeyType.pkType(for: pk, coin: coin)
            switch utxoPkType {
            case .some(let pkType):
                switch pkType {
                case .hex:
                    self.raw = Data(hex: pk)
                case .wifUncompressed:
                    let decodedPk = Base58.decode(pk) ?? Data()
                    let wifData = decodedPk.dropLast(4).dropFirst()
                    self.raw = wifData
                case .wifCompressed:
                    let decodedPk = Base58.decode(pk) ?? Data()
                    let wifData = decodedPk.dropLast(4).dropFirst().dropLast()
                    self.raw = wifData
                }
            case .none:
                return nil
            }

        }
        self.chainCode = Data(capacity: 32)
        self.index = 0
        self.coin = coin
        self.keyType = .nonHd
    }
    
    public init(privateKey: Data, chainCode: Data, index: UInt32, coin: Coin) {
        self.raw = privateKey
        self.chainCode = chainCode
        self.index = index
        self.coin = coin
        self.keyType = .hd
    }
    
    public var publicKey: PublicKey {
        return PublicKey(privateKey: raw, coin: coin)
    }
    
    public func wifCompressed() -> String {
        var data = Data()
        data += coin.wifAddressPrefix
        data += raw
        data += UInt8(0x01)
        data += data.doubleSHA256.prefix(4)
        return Base58.encode(data)
    }
    
    public func wifUncompressed() -> String {
        var data = Data()
        data += coin.wifAddressPrefix
        data += raw
        data += data.doubleSHA256.prefix(4)
        return Base58.encode(data)
    }
    
    public func get() -> String {
        switch self.coin {
        case .bitcoin: fallthrough
        case .litecoin: fallthrough
        case .dash: fallthrough
        case .bitcoinCash:
            return self.wifCompressed()
        case .dogecoin:
            return self.wifUncompressed()
        case .ethereum:
            return self.raw.toHexString()
        }
    }
    
    public func derived(at node:DerivationNode) -> PrivateKey {
        guard keyType == .hd else { fatalError() }
        let edge: UInt32 = 0x80000000
        guard (edge & node.index) == 0 else { fatalError("Invalid child index") }
        
        var data = Data()
        switch node {
        case .hardened:
            data += UInt8(0)
            data += raw
        case .notHardened:
            data += Crypto.generatePublicKey(data: raw, compressed: true)
        }
        
        let derivingIndex = CFSwapInt32BigToHost(node.hardens ? (edge | node.index) : node.index)
        data += derivingIndex
        
        let digest = Crypto.HMACSHA512(key: chainCode, data: data)
        let factor = BInt(data: digest[0..<32])
        
        let curveOrder = BInt(hex: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")!
        let derivedPrivateKey = ((BInt(data: raw) + factor) % curveOrder).data
        let derivedChainCode = digest[32..<64]
        return PrivateKey(
            privateKey: derivedPrivateKey,
            chainCode: derivedChainCode,
            index: derivingIndex,
            coin: coin
        )
    }
    
    public func derivedPublic() -> PrivateKey {
        guard keyType == .hd else { fatalError() }
        let data = raw + Data([UInt8(0),UInt8(0),UInt8(0),UInt8(1)])
        let digest = Crypto.HMACSHA512(key: chainCode, data: data)
        let ki = Crypto.generatePublicKey(data: digest[0..<32], compressed: true)
        let derivedPrivateKey = sum(publicKey1: ki, publicKey2: raw)
        let derivedChainCode = digest[32..<64]
        
        return PrivateKey(
            privateKey: derivedPrivateKey,
            chainCode: derivedChainCode,
            index: 1,
            coin: coin
        )
    }
    
    public func sign(hash: Data) throws -> Data {
        return try Crypto.sign(hash, privateKey: raw)
    }
    
    private func decompressKey(data: Data) -> Data {
        let encrypter = EllipticCurveEncrypterSecp256k1()
        var publicKey = encrypter.parsePublicKey(data)!
        return encrypter.export(publicKey: &publicKey, compressed: false)
    }
    
    private func compressKey(data: Data) -> Data {
        let encrypter = EllipticCurveEncrypterSecp256k1()
        var publicKey = encrypter.parsePublicKey(data)!
        return encrypter.export(publicKey: &publicKey, compressed: true)
    }
    
    
    private func sum(publicKey1: Data, publicKey2: Data) -> Data {
        let decompressed1 = decompressKey(data: publicKey1)
        let decompressed2 = decompressKey(data: publicKey2)

        let length = (decompressed1.count - 1)/2
        let x1 = BInt(data: decompressed1[1...length])
        let y1 = BInt(data: decompressed1[(length+1)...])
        let x2 = BInt(data: decompressed2[1...length])
        let y2 = BInt(data: decompressed2[(length+1)...])

        let modP = BInt(hex: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")!
        let a = y2 - y1
        let b = x2 - x1
        let p = modP - BInt(integerLiteral: 2)
        let lambda = (BInt.mod_exp(b, p, modP) * a) % modP
        let x3 = (lambda * lambda - x1 - x2) % modP
        let y3 = ((lambda * (x1 - x3) - y1)) % modP
    
        let uncompressed = Data([UInt8(0x04)]) + x3.data + y3.data
        let compressed = compressKey(data: uncompressed)
        return compressed
    }
}

