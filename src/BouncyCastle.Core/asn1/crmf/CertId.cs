using BouncyCastle.Core.Port;
using org.bouncycastle.asn1.x509;

namespace org.bouncycastle.asn1.crmf
{

	
	public class CertId : ASN1Object
	{
		private GeneralName issuer;
		private ASN1Integer serialNumber;

		private CertId(ASN1Sequence seq)
		{
			issuer = GeneralName.getInstance(seq.getObjectAt(0));
			serialNumber = ASN1Integer.getInstance(seq.getObjectAt(1));
		}

		public static CertId getInstance(object o)
		{
			if (o is CertId)
			{
				return (CertId)o;
			}

			if (o != null)
			{
				return new CertId(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public static CertId getInstance(ASN1TaggedObject obj, bool isExplicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, isExplicit));
		}

		public CertId(GeneralName issuer, BigInteger serialNumber) : this(issuer, new ASN1Integer(serialNumber))
		{
		}

		public CertId(GeneralName issuer, ASN1Integer serialNumber)
		{
			this.issuer = issuer;
			this.serialNumber = serialNumber;
		}

		public virtual GeneralName getIssuer()
		{
			return issuer;
		}

		public virtual ASN1Integer getSerialNumber()
		{
			return serialNumber;
		}

		/// <summary>
		/// <pre>
		/// CertId ::= SEQUENCE {
		///                 issuer           GeneralName,
		///                 serialNumber     INTEGER }
		/// </pre> </summary>
		/// <returns> a basic ASN.1 object representation. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(issuer);
			v.add(serialNumber);

			return new DERSequence(v);
		}
	}

}