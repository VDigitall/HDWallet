//
//  Transaction+Script.swift
//  HDWalletKit
//
//  Created by Andrew Son on 01/12/20.
//  Copyright © 2020 Essentia. All rights reserved.
//

import Foundation

public extension Transaction {
	public func hashForSignature(index: Int, script: Script, type: SighashType) throws -> Data {
		try hashForSignature(index: index, scriptData: script, sigHashType: type.uint8)
	}
	
	public func hashForSignature(index: Int, scriptData: Script, sigHashType: UInt8) throws -> Data {
		var connectedScript = scriptData
		var inputs = self.inputs.map { TransactionInput(previousOutput: $0.previousOutput, signatureScript: Data(), sequence: $0.sequence) }
		var outputs = self.outputs
		
		// This step has no purpose beyond being synchronized with Bitcoin Core's bugs. OP_CODESEPARATOR
		// is a legacy holdover from a previous, broken design of executing scripts that shipped in Bitcoin 0.1.
		// It was seriously flawed and would have let anyone take anyone elses money. Later versions switched to
		// the design we use today where scripts are executed independently but share a stack. This left the
		// OP_CODESEPARATOR instruction having no purpose as it was only meant to be used internally, not actually
		// ever put into scripts. Deleting OP_CODESEPARATOR is a step that should never be required but if we don't
		// do it, we could split off the best chain.
		connectedScript = try connectedScript.deleteOccurrences(of: .OP_CODESEPARATOR)
		
		// Set the input to the script of its output. Bitcoin Core does this but the step has no obvious purpose as
		// the signature covers the hash of the prevout transaction which obviously includes the output script
		// already. Perhaps it felt safer to him in some way, or is another leftover from how the code was written.
		let prevInput = inputs[index]
		let input = TransactionInput(previousOutput: prevInput.previousOutput, signatureScript: connectedScript.data, sequence: prevInput.sequence)
		inputs[index] = input
		
		func zeroSequenceInputs() -> [TransactionInput] {
			self.inputs.enumerated().map{ (item) -> TransactionInput in
				if item.offset != index {
					let oldOutput = item.element
					return TransactionInput(previousOutput: oldOutput.previousOutput, signatureScript: oldOutput.signatureScript, sequence: 0)
				} else {
					return input
				}
			}
		}
		
		let sigHashToCompare = sigHashType & 0x1f
		if sigHashToCompare == SighashType.BTC.NONE.uint8 {
			// SIGHASH_NONE means no outputs are signed at all - the signature is effectively for a "blank cheque".
			outputs = []
			// The signature isn't broken by new versions of the transaction issued by other parties.
			inputs = zeroSequenceInputs()
		} else if sigHashToCompare == SighashType.BTC.SINGLE.uint8 {
			// SIGHASH_SINGLE means only sign the output at the same index as the input (ie, my output).
			if index >= self.outputs.count {
				// The input index is beyond the number of outputs, it's a buggy signature made by a broken
				// Bitcoin implementation. Bitcoin Core also contains a bug in handling this case:
				// any transaction output that is signed in this case will result in both the signed output
				// and any future outputs to this public key being steal-able by anyone who has
				// the resulting signature and the public key (both of which are part of the signed tx input).

				// Bitcoin Core's bug is that SignatureHash was supposed to return a hash and on this codepath it
				// actually returns the constant "1" to indicate an error, which is never checked for. Oops.
				return Data(hex: "0100000000000000000000000000000000000000000000000000000000000000")
			}
			// In SIGHASH_SINGLE the outputs after the matching input index are deleted, and the outputs before
			// that position are "nulled out". Unintuitively, the value in a "null" transaction is set to -1.
			outputs = [TransactionOutput]()
			for (itemIndex, item) in self.outputs.enumerated() {
				guard itemIndex <= index else { break }
				if itemIndex == index {
					outputs.append(item)
				}
				outputs.append(TransactionOutput(value: UInt64(bitPattern: -1), lockingScript: Data()))
			}
			// The signature isn't broken by new versions of the transaction issued by other parties.
			inputs = zeroSequenceInputs()
		}
		
		if sigHashType == SighashType.BTC.ANYONECANPAY.uint8 {
			// SIGHASH_ANYONECANPAY means the signature in the input is not broken by changes/additions/removals
			// of other inputs. For example, this is useful for building assurance contracts.
			inputs = [input]
		}
		
		let txToSerialize = Transaction(version: version, inputs: inputs, outputs: outputs, lockTime: lockTime)
		var serializedData = txToSerialize.serialized()
		// We also have to write a hash type (sigHashType is actually an unsigned char)
		serializedData += Int(0x000000ff & sigHashType).bytes4LE
		// Note that this is NOT reversed to ensure it will be signed correctly. If it were to be printed out
		// however then we would expect that it is IS reversed.
		let hash = serializedData.doubleSHA256
		return hash
	}
}

extension Int {
	/// return 2 bytes of integer. LittleEndian format
	public var bytes2LE: Data {
		let clamped = UInt16(clamping: self)
		let data = withUnsafeBytes(of: clamped) { Data($0) }
		return data
	}
	
	/// return 4 bytes of integer. LittleEndian format
	public var bytes4LE: Data {
		let clamped = UInt32(clamping: self)
		let data = withUnsafeBytes(of: clamped) { Data($0) }
		return data
	}
	
	/// return 8 bytes of integer. LittleEndian  format
	public var bytes8LE: Data {
		let data = withUnsafeBytes(of: self) { Data($0) }
		return data
	}
}
