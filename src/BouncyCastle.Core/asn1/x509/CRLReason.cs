using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.x509
{

	using Integers = org.bouncycastle.util.Integers;

	/// <summary>
	/// The CRLReason enumeration.
	/// <pre>
	/// CRLReason ::= ENUMERATED {
	///  unspecified             (0),
	///  keyCompromise           (1),
	///  cACompromise            (2),
	///  affiliationChanged      (3),
	///  superseded              (4),
	///  cessationOfOperation    (5),
	///  certificateHold         (6),
	///  removeFromCRL           (8),
	///  privilegeWithdrawn      (9),
	///  aACompromise           (10)
	/// }
	/// </pre>
	/// </summary>
	public class CRLReason : ASN1Object
	{
		/// @deprecated use lower case version 
		public const int UNSPECIFIED = 0;
		/// @deprecated use lower case version 
		public const int KEY_COMPROMISE = 1;
		/// @deprecated use lower case version 
		public const int CA_COMPROMISE = 2;
		/// @deprecated use lower case version 
		public const int AFFILIATION_CHANGED = 3;
		/// @deprecated use lower case version 
		public const int SUPERSEDED = 4;
		/// @deprecated use lower case version 
		public const int CESSATION_OF_OPERATION = 5;
		/// @deprecated use lower case version 
		public const int CERTIFICATE_HOLD = 6;
		/// @deprecated use lower case version 
		public const int REMOVE_FROM_CRL = 8;
		/// @deprecated use lower case version 
		public const int PRIVILEGE_WITHDRAWN = 9;
		/// @deprecated use lower case version 
		public const int AA_COMPROMISE = 10;

		public const int unspecified = 0;
		public const int keyCompromise = 1;
		public const int cACompromise = 2;
		public const int affiliationChanged = 3;
		public const int superseded = 4;
		public const int cessationOfOperation = 5;
		public const int certificateHold = 6;
		// 7 -> unknown
		public const int removeFromCRL = 8;
		public const int privilegeWithdrawn = 9;
		public const int aACompromise = 10;

		private static readonly string[] reasonString = new string[] {"unspecified", "keyCompromise", "cACompromise", "affiliationChanged", "superseded", "cessationOfOperation", "certificateHold", "unknown", "removeFromCRL", "privilegeWithdrawn", "aACompromise"};

		private static readonly Hashtable table = new Hashtable();

		private ASN1Enumerated value;

		public static CRLReason getInstance(object o)
		{
			if (o is CRLReason)
			{
				return (CRLReason)o;
			}
			else if (o != null)
			{
				return lookup(ASN1Enumerated.getInstance(o).getValue().intValue());
			}

			return null;
		}

		private CRLReason(int reason)
		{
			value = new ASN1Enumerated(reason);
		}

		public override string ToString()
		{
			string str;
			int reason = getValue().intValue();
			if (reason < 0 || reason > 10)
			{
				str = "invalid";
			}
			else
			{
				str = reasonString[reason];
			}
			return "CRLReason: " + str;
		}

		public virtual BigInteger getValue()
		{
			return value.getValue();
		}

		public override ASN1Primitive toASN1Primitive()
		{
			return value;
		}

		public static CRLReason lookup(int value)
		{
			int? idx = Integers.valueOf(value);

			if (!table.containsKey(idx))
			{
				table.put(idx, new CRLReason(value));
			}

			return (CRLReason)table.get(idx);
		}
	}

}