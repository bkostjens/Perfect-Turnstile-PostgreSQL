//
//  Account.swift
//  PerfectTurnstilePostgreSQL
//
//  Created by Jonathan Guthrie on 2016-10-17.
//
//

import Turnstile
import TurnstileCrypto
import PostgresStORM
import StORM

/// Provides the Account structure for Perfect Turnstile
open class AuthAccount : PostgresStORM, Account {

	/// The User account's Unique ID
	public var uniqueID: String = ""

	/// The username with which the user will log in with
	public var username: String = ""

	/// The password to be set for the user
	public var password: String = ""

	/// Stored Facebook ID when logging in with Facebook
	public var facebookID: String = ""

	/// Stored Google ID when logging in with Google
	public var googleID: String = ""

	/// Optional first name
	public var firstname: String = ""

	/// Optional last name
	public var lastname: String = ""

	/// Optional email
	public var email: String = ""

	/// Internal container variable for the current Token object
	public var internal_token: AccessTokenStore = AccessTokenStore()

	/// The table to store the data
	override open func table() -> String {
		return "users"
	}

	/// Shortcut to store the id
	public func id(_ newid: String) {
		uniqueID = newid
	}

	/// Set incoming data from database to object
	override open func to(_ this: StORMRow) {
		uniqueID	= this.data["id"] as? String ?? ""
		username	= this.data["username"] as? String ?? ""
		password	= this.data["password"] as? String ?? ""
		facebookID	= this.data["facebookid"] as? String ?? ""
		googleID	= this.data["googleid"] as? String ?? ""
		firstname	= this.data["firstname"] as? String ?? ""
		lastname	= this.data["lastname"] as? String ?? ""
		email		= this.data["email"] as? String ?? ""
	}

	/// Iterate through rows and set to object data
	public func rows() -> [AuthAccount] {
		var rows = [AuthAccount]()
		for i in 0..<self.results.rows.count {
			let row = AuthAccount()
			row.to(self.results.rows[i])
			rows.append(row)
		}
		return rows
	}

	/// Forces a create with a hashed password
	func make() throws {
		do {
			password = BCrypt.hash(password: password)
			try create() // can't use save as the id is populated
		} catch {
			print(error)
		}
	}

	/// Performs a find on supplied username, and matches hashed password
	open func get(_ un: String, _ pw: String) throws -> AuthAccount {
		let cursor = StORMCursor(limit: 1, offset: 0)
		do {
			try select(whereclause: "username = $1", params: [un], orderby: [], cursor: cursor)
			if self.results.rows.count == 0 {
				throw StORMError.noRecordFound
			}
			to(self.results.rows[0])
		} catch {
			print(error)
			throw StORMError.noRecordFound
		}
		if try BCrypt.verify(password: pw, matchesHash: password) {
			return self
		} else {
			throw StORMError.noRecordFound
		}

	}

	/// Returns a true / false depending on if the username exits in the database.
	func exists(_ un: String) -> Bool {
		do {
			try select(whereclause: "username = $1", params: [un], orderby: [], cursor: StORMCursor(limit: 1, offset: 0))
			if results.rows.count == 1 {
				return true
			} else {
				return false
			}
		} catch {
			print("Exists error: \(error)")
			return false
		}
	}
}

public struct AuthenticationConfig {
    public var inclusions = [String]()
    public var exclusions = [String]()
    
    public var denied: String?
    
    public init() {}
    
    public mutating func include(_ str: String) {
        inclusions.append(str)
    }
    public mutating func include(_ arr: [String]) {
        inclusions += arr
    }
    public mutating func exclude(_ str: String) {
        exclusions.append(str)
    }
    public mutating func exclude(_ arr: [String]) {
        exclusions += arr
    }
}

import PerfectHTTP
import SwiftString


public struct AuthFilter: HTTPRequestFilter {
    var authenticationConfig = AuthenticationConfig()
    
    public init(_ cfg: AuthenticationConfig) {
        authenticationConfig = cfg
    }
    
    public func filter(request: HTTPRequest, response: HTTPResponse, callback: (HTTPRequestFilterResult) -> ()) {
        //        guard let denied = authenticationConfig.denied else {
        //            callback(.continue(request, response))
        //            return
        //        }
        var checkAuth = false
        let wildcardInclusions = authenticationConfig.inclusions.filter({$0.contains("*")})
        let wildcardExclusions = authenticationConfig.exclusions.filter({$0.contains("*")})
        
        // check if specifically in inclusions
        if authenticationConfig.inclusions.contains(request.path) { checkAuth = true }
        // check if covered by a wildcard
        for wInc in wildcardInclusions {
            if request.path.startsWith(wInc.split("*")[0]) { checkAuth = true }
        }
        
        // ignore check if sepecified in exclusions
        if authenticationConfig.exclusions.contains(request.path) { checkAuth = false }
        // check if covered by a wildcard
        for wInc in wildcardExclusions {
            if request.path.startsWith(wInc.split("*")[0]) { checkAuth = false }
        }
        
        if checkAuth && request.user.authenticated {
            callback(.continue(request, response))
            return
        } else if checkAuth {
            response.status = .unauthorized
            callback(.halt(request, response))
            return
        }
        callback(.continue(request, response))
    }
}


