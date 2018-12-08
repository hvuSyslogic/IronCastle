using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cmp
{

	public class PKIConfirmContent : ASN1Object
	{
		private ASN1Null val;

		private PKIConfirmContent(ASN1Null val)
		{
			this.val = val;
		}

		public static PKIConfirmContent getInstance(object o)
		{
			if (o == null || o is PKIConfirmContent)
			{
				return (PKIConfirmContent)o;
			}

			if (o is ASN1Null)
			{
				return new PKIConfirmContent((ASN1Null)o);
			}

			throw new IllegalArgumentException("Invalid object: " + o.GetType().getName());
		}

		public PKIConfirmContent()
		{
			val = DERNull.INSTANCE;
		}

		/// <summary>
		/// <pre>
		/// PKIConfirmContent ::= NULL
		/// </pre> </summary>
		/// <returns> a basic ASN.1 object representation. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			return val;
		}
	}

}