using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.cmc
{


	/// <summary>
	/// <pre>
	/// CMCFailInfo ::= INTEGER {
	///     badAlg          (0),
	///     badMessageCheck (1),
	///     badRequest      (2),
	///     badTime         (3),
	///     badCertId       (4),
	///     unsupportedExt  (5),
	///     mustArchiveKeys (6),
	///     badIdentity     (7),
	///     popRequired     (8),
	///     popFailed       (9),
	///     noKeyReuse      (10),
	///     internalCAError (11),
	///     tryLater        (12),
	///     authDataFail    (13)
	/// }
	/// </pre>
	/// </summary>
	public class CMCFailInfo : ASN1Object
	{
		public static readonly CMCFailInfo badAlg = new CMCFailInfo(new ASN1Integer(0));
		public static readonly CMCFailInfo badMessageCheck = new CMCFailInfo(new ASN1Integer(1));
		public static readonly CMCFailInfo badRequest = new CMCFailInfo(new ASN1Integer(2));
		public static readonly CMCFailInfo badTime = new CMCFailInfo(new ASN1Integer(3));
		public static readonly CMCFailInfo badCertId = new CMCFailInfo(new ASN1Integer(4));
		public static readonly CMCFailInfo unsupportedExt = new CMCFailInfo(new ASN1Integer(5));
		public static readonly CMCFailInfo mustArchiveKeys = new CMCFailInfo(new ASN1Integer(6));
		public static readonly CMCFailInfo badIdentity = new CMCFailInfo(new ASN1Integer(7));
		public static readonly CMCFailInfo popRequired = new CMCFailInfo(new ASN1Integer(8));
		public static readonly CMCFailInfo popFailed = new CMCFailInfo(new ASN1Integer(9));
		public static readonly CMCFailInfo noKeyReuse = new CMCFailInfo(new ASN1Integer(10));
		public static readonly CMCFailInfo internalCAError = new CMCFailInfo(new ASN1Integer(11));
		public static readonly CMCFailInfo tryLater = new CMCFailInfo(new ASN1Integer(12));
		public static readonly CMCFailInfo authDataFail = new CMCFailInfo(new ASN1Integer(13));

		private static Map range = new HashMap();

		static CMCFailInfo()
		{
			range.put(badAlg.value, badAlg);
			range.put(badMessageCheck.value, badMessageCheck);
			range.put(badRequest.value, badRequest);
			range.put(badTime.value, badTime);
			range.put(badCertId.value, badCertId);
			range.put(popRequired.value, popRequired);
			range.put(unsupportedExt.value, unsupportedExt);
			range.put(mustArchiveKeys.value, mustArchiveKeys);
			range.put(badIdentity.value, badIdentity);
			range.put(popRequired.value, popRequired);
			range.put(popFailed.value, popFailed);
			range.put(badCertId.value, badCertId);
			range.put(popRequired.value, popRequired);
			range.put(noKeyReuse.value, noKeyReuse);
			range.put(internalCAError.value, internalCAError);
			range.put(tryLater.value, tryLater);
			range.put(authDataFail.value, authDataFail);
		}

		private readonly ASN1Integer value;

		private CMCFailInfo(ASN1Integer value)
		{
			 this.value = value;
		}

		public static CMCFailInfo getInstance(object o)
		{
			if (o is CMCFailInfo)
			{
				return (CMCFailInfo)o;
			}

			if (o != null)
			{
				CMCFailInfo status = (CMCFailInfo)range.get(ASN1Integer.getInstance(o));

				if (status != null)
				{
					return status;
				}

				throw new IllegalArgumentException("unknown object in getInstance(): " + o.GetType().getName());
			}

			return null;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			return value;
		}
	}

}