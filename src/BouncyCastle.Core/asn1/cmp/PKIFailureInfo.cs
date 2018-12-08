namespace org.bouncycastle.asn1.cmp
{

	/// <summary>
	/// <pre>
	/// PKIFailureInfo ::= BIT STRING {
	/// badAlg               (0),
	///   -- unrecognized or unsupported Algorithm Identifier
	/// badMessageCheck      (1), -- integrity check failed (e.g., signature did not verify)
	/// badRequest           (2),
	///   -- transaction not permitted or supported
	/// badTime              (3), -- messageTime was not sufficiently close to the system time, as defined by local policy
	/// badCertId            (4), -- no certificate could be found matching the provided criteria
	/// badDataFormat        (5),
	///   -- the data submitted has the wrong format
	/// wrongAuthority       (6), -- the authority indicated in the request is different from the one creating the response token
	/// incorrectData        (7), -- the requester's data is incorrect (for notary services)
	/// missingTimeStamp     (8), -- when the timestamp is missing but should be there (by policy)
	/// badPOP               (9)  -- the proof-of-possession failed
	/// certRevoked         (10),
	/// certConfirmed       (11),
	/// wrongIntegrity      (12),
	/// badRecipientNonce   (13), 
	/// timeNotAvailable    (14),
	///   -- the TSA's time source is not available
	/// unacceptedPolicy    (15),
	///   -- the requested TSA policy is not supported by the TSA
	/// unacceptedExtension (16),
	///   -- the requested extension is not supported by the TSA
	/// addInfoNotAvailable (17)
	///   -- the additional information requested could not be understood
	///   -- or is not available
	/// badSenderNonce      (18),
	/// badCertTemplate     (19),
	/// signerNotTrusted    (20),
	/// transactionIdInUse  (21),
	/// unsupportedVersion  (22),
	/// notAuthorized       (23),
	/// systemUnavail       (24),    
	/// systemFailure       (25),
	///   -- the request cannot be handled due to system failure
	/// duplicateCertReq    (26) 
	/// </pre>
	/// </summary>
	public class PKIFailureInfo : DERBitString
	{
		public static readonly int badAlg = (1 << 7); // unrecognized or unsupported Algorithm Identifier
		public static readonly int badMessageCheck = (1 << 6); // integrity check failed (e.g., signature did not verify)
		public static readonly int badRequest = (1 << 5);
		public static readonly int badTime = (1 << 4); // -- messageTime was not sufficiently close to the system time, as defined by local policy
		public static readonly int badCertId = (1 << 3); // no certificate could be found matching the provided criteria
		public static readonly int badDataFormat = (1 << 2);
		public static readonly int wrongAuthority = (1 << 1); // the authority indicated in the request is different from the one creating the response token
		public const int incorrectData = 1; // the requester's data is incorrect (for notary services)
		public static readonly int missingTimeStamp = (1 << 15); // when the timestamp is missing but should be there (by policy)
		public static readonly int badPOP = (1 << 14); // the proof-of-possession failed
		public static readonly int certRevoked = (1 << 13);
		public static readonly int certConfirmed = (1 << 12);
		public static readonly int wrongIntegrity = (1 << 11);
		public static readonly int badRecipientNonce = (1 << 10);
		public static readonly int timeNotAvailable = (1 << 9); // the TSA's time source is not available
		public static readonly int unacceptedPolicy = (1 << 8); // the requested TSA policy is not supported by the TSA
		public static readonly int unacceptedExtension = (1 << 23); //the requested extension is not supported by the TSA
		public static readonly int addInfoNotAvailable = (1 << 22); //the additional information requested could not be understood or is not available
		public static readonly int badSenderNonce = (1 << 21);
		public static readonly int badCertTemplate = (1 << 20);
		public static readonly int signerNotTrusted = (1 << 19);
		public static readonly int transactionIdInUse = (1 << 18);
		public static readonly int unsupportedVersion = (1 << 17);
		public static readonly int notAuthorized = (1 << 16);
		public static readonly int systemUnavail = (1 << 31);
		public static readonly int systemFailure = (1 << 30); //the request cannot be handled due to system failure
		public static readonly int duplicateCertReq = (1 << 29);

		/// @deprecated use lower case version 
		public static readonly int BAD_ALG = badAlg; // unrecognized or unsupported Algorithm Identifier
		/// @deprecated use lower case version 
		public static readonly int BAD_MESSAGE_CHECK = badMessageCheck;
		/// @deprecated use lower case version 
		public static readonly int BAD_REQUEST = badRequest; // transaction not permitted or supported
		/// @deprecated use lower case version 
		public static readonly int BAD_TIME = badTime;
		/// @deprecated use lower case version 
		public static readonly int BAD_CERT_ID = badCertId;
		/// @deprecated use lower case version 
		public static readonly int BAD_DATA_FORMAT = badDataFormat; // the data submitted has the wrong format
		/// @deprecated use lower case version 
		public static readonly int WRONG_AUTHORITY = wrongAuthority;
		/// @deprecated use lower case version 
		public const int INCORRECT_DATA = incorrectData;
		/// @deprecated use lower case version 
		public static readonly int MISSING_TIME_STAMP = missingTimeStamp;
		/// @deprecated use lower case version 
		public static readonly int BAD_POP = badPOP;
		/// @deprecated use lower case version 
		public static readonly int TIME_NOT_AVAILABLE = timeNotAvailable;
		/// @deprecated use lower case version 
		public static readonly int UNACCEPTED_POLICY = unacceptedPolicy;
		/// @deprecated use lower case version 
		public static readonly int UNACCEPTED_EXTENSION = unacceptedExtension;
		/// @deprecated use lower case version 
		public static readonly int ADD_INFO_NOT_AVAILABLE = addInfoNotAvailable;
		/// @deprecated use lower case version 
		public static readonly int SYSTEM_FAILURE = systemFailure;
		/// <summary>
		/// Basic constructor.
		/// </summary>
		public PKIFailureInfo(int info) : base(getBytes(info), getPadBits(info))
		{
		}

		public PKIFailureInfo(DERBitString info) : base(info.getBytes(), info.getPadBits())
		{
		}

		public override string ToString()
		{
			return "PKIFailureInfo: 0x" + this.intValue().ToString("x");
		}
	}

}