//
//  Tokens.swift
//  PerfectTurnstilePostgreSQL
//
//  Created by Jonathan Guthrie on 2016-10-17.
//
//

import PostgresStORM
import StORM
import Foundation
import SwiftRandom
import Turnstile


/// Class for handling the tokens that are used for JSON API and Web authentication
open class AccessTokenStore : PostgresStORM {

	/// The token itself.
	public var token: String = ""

	/// The userid relates to the Users object UniqueID
	public var userid: String = ""

	/// Integer relaing to the created date/time
	public var created: Double = 0

	/// Integer relaing to the last updated date/time
	public var updated: Double = 0

	/// Idle period specified when token was created
	public var idle: Double = 7776000 // 86400 seconds = 1 day

	/// Table name used to store Tokens
	override open func table() -> String {
		return "tokens"
	}


	/// Set incoming data from database to object
	open override func to(_ this: StORMRow) {
		if let val = this.data["token"]		{ token		= val as! String }
		if let val = this.data["userid"]	{ userid	= val as! String }
		if let val = this.data["created"]	{ created	= val as! Double }
		if let val = this.data["updated"]	{ updated	= val as! Double }
		if let val = this.data["idle"]		{ idle		= val as! Double}

	}

	/// Iterate through rows and set to object data
	func rows() -> [AccessTokenStore] {
		var rows = [AccessTokenStore]()
		for i in 0..<self.results.rows.count {
			let row = AccessTokenStore()
			row.to(self.results.rows[i])
			rows.append(row)
		}
		return rows
	}

	private func now() -> Double {
		return Date().timeIntervalSince1970
	}

	/// Checks to see if the token is active
	/// Upticks the updated int to keep it alive.
	public func check() -> Bool? {
		if (updated + idle) < now() { return false } else {
			do {
				updated = now()
				try save()
			} catch {
				print(error)
			}
			return true
		}
	}

	/// Triggers creating a new token.
	public func new(_ u: String) -> String {
		let rand = URandom()
		token = rand.secureToken
		//token = token.replacingOccurrences(of: "-", with: "a")
		userid = u
		created = now()
		updated = now()
		do {
			try create()
		} catch {
			print(error)
		}
		return token
	}
}
