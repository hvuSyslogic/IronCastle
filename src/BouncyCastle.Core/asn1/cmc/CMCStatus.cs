using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.cmc
{


	/// <summary>
	/// <pre>
	/// 
	/// CMCStatus ::= INTEGER {
	///    success         (0),
	///    failed          (2),
	///    pending         (3),
	///    noSupport       (4),
	///    confirmRequired (5),
	///    popRequired     (6),
	///    partial         (7)
	/// }
	/// </pre>
	/// </summary>
	public class CMCStatus : ASN1Object
	{
		public static readonly CMCStatus success = new CMCStatus(new ASN1Integer(0));
		public static readonly CMCStatus failed = new CMCStatus(new ASN1Integer(2));
		public static readonly CMCStatus pending = new CMCStatus(new ASN1Integer(3));
		public static readonly CMCStatus noSupport = new CMCStatus(new ASN1Integer(4));
		public static readonly CMCStatus confirmRequired = new CMCStatus(new ASN1Integer(5));
		public static readonly CMCStatus popRequired = new CMCStatus(new ASN1Integer(6));
		public static readonly CMCStatus partial = new CMCStatus(new ASN1Integer(7));

		private static Map range = new HashMap();

		static CMCStatus()
		{
			range.put(success.value, success);
			range.put(failed.value, failed);
			range.put(pending.value, pending);
			range.put(noSupport.value, noSupport);
			range.put(confirmRequired.value, confirmRequired);
			range.put(popRequired.value, popRequired);
			range.put(partial.value, partial);
		}

		private readonly ASN1Integer value;

		private CMCStatus(ASN1Integer value)
		{
			 this.value = value;
		}

		public static CMCStatus getInstance(object o)
		{
			if (o is CMCStatus)
			{
				return (CMCStatus)o;
			}

			if (o != null)
			{
				CMCStatus status = (CMCStatus)range.get(ASN1Integer.getInstance(o));

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