namespace org.bouncycastle.asn1.x509
{

	/// <summary>
	/// The ReasonFlags object.
	/// <pre>
	/// ReasonFlags ::= BIT STRING {
	///      unused                  (0),
	///      keyCompromise           (1),
	///      cACompromise            (2),
	///      affiliationChanged      (3),
	///      superseded              (4),
	///      cessationOfOperation    (5),
	///      certificateHold         (6),
	///      privilegeWithdrawn      (7),
	///      aACompromise            (8) }
	/// </pre>
	/// </summary>
	public class ReasonFlags : DERBitString
	{
		/// @deprecated use lower case version 
		public static readonly int UNUSED = (1 << 7);
		/// @deprecated use lower case version 
		public static readonly int KEY_COMPROMISE = (1 << 6);
		/// @deprecated use lower case version 
		public static readonly int CA_COMPROMISE = (1 << 5);
		/// @deprecated use lower case version 
		public static readonly int AFFILIATION_CHANGED = (1 << 4);
		/// @deprecated use lower case version 
		public static readonly int SUPERSEDED = (1 << 3);
		/// @deprecated use lower case version 
		public static readonly int CESSATION_OF_OPERATION = (1 << 2);
		/// @deprecated use lower case version 
		public static readonly int CERTIFICATE_HOLD = (1 << 1);
		/// @deprecated use lower case version 
		public static readonly int PRIVILEGE_WITHDRAWN = (1 << 0);
		/// @deprecated use lower case version 
		public static readonly int AA_COMPROMISE = (1 << 15);

		public static readonly int unused = (1 << 7);
		public static readonly int keyCompromise = (1 << 6);
		public static readonly int cACompromise = (1 << 5);
		public static readonly int affiliationChanged = (1 << 4);
		public static readonly int superseded = (1 << 3);
		public static readonly int cessationOfOperation = (1 << 2);
		public static readonly int certificateHold = (1 << 1);
		public static readonly int privilegeWithdrawn = (1 << 0);
		public static readonly int aACompromise = (1 << 15);

		/// <param name="reasons"> - the bitwise OR of the Key Reason flags giving the
		/// allowed uses for the key. </param>
		public ReasonFlags(int reasons) : base(getBytes(reasons), getPadBits(reasons))
		{
		}

		public ReasonFlags(DERBitString reasons) : base(reasons.getBytes(), reasons.getPadBits())
		{
		}
	}

}