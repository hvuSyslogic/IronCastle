using BouncyCastle.Core.Port;

namespace org.bouncycastle.asn1.ocsp
{


	public class OCSPResponseStatus : ASN1Object
	{
		public const int SUCCESSFUL = 0;
		public const int MALFORMED_REQUEST = 1;
		public const int INTERNAL_ERROR = 2;
		public const int TRY_LATER = 3;
		public const int SIG_REQUIRED = 5;
		public const int UNAUTHORIZED = 6;

		private ASN1Enumerated value;

		/// <summary>
		/// The OCSPResponseStatus enumeration.
		/// <pre>
		/// OCSPResponseStatus ::= ENUMERATED {
		///     successful            (0),  --Response has valid confirmations
		///     malformedRequest      (1),  --Illegal confirmation request
		///     internalError         (2),  --Internal error in issuer
		///     tryLater              (3),  --Try again later
		///                                 --(4) is not used
		///     sigRequired           (5),  --Must sign the request
		///     unauthorized          (6)   --Request unauthorized
		/// }
		/// </pre>
		/// </summary>
		public OCSPResponseStatus(int value) : this(new ASN1Enumerated(value))
		{
		}

		private OCSPResponseStatus(ASN1Enumerated value)
		{
			this.value = value;
		}

		public static OCSPResponseStatus getInstance(object obj)
		{
			if (obj is OCSPResponseStatus)
			{
				return (OCSPResponseStatus)obj;
			}
			else if (obj != null)
			{
				return new OCSPResponseStatus(ASN1Enumerated.getInstance(obj));
			}

			return null;
		}

		public virtual BigInteger getValue()
		{
			return value.getValue();
		}

		public override ASN1Primitive toASN1Primitive()
		{
			return value;
		}
	}

}