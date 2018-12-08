using BouncyCastle.Core.Port;

namespace org.bouncycastle.asn1.x509
{


	/// <summary>
	/// The CRLNumber object.
	/// <pre>
	/// CRLNumber::= INTEGER(0..MAX)
	/// </pre>
	/// </summary>
	public class CRLNumber : ASN1Object
	{
		private BigInteger number;

		public CRLNumber(BigInteger number)
		{
			this.number = number;
		}

		public virtual BigInteger getCRLNumber()
		{
			return number;
		}

		public override string ToString()
		{
			return "CRLNumber: " + getCRLNumber();
		}

		public override ASN1Primitive toASN1Primitive()
		{
			return new ASN1Integer(number);
		}

		public static CRLNumber getInstance(object o)
		{
			if (o is CRLNumber)
			{
				return (CRLNumber)o;
			}
			else if (o != null)
			{
				return new CRLNumber(ASN1Integer.getInstance(o).getValue());
			}

			return null;
		}
	}

}