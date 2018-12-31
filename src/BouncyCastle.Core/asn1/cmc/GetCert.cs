using BouncyCastle.Core.Port;
using org.bouncycastle.asn1.x509;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cmc
{

	
	/// <summary>
	/// <pre>
	///      id-cmc-getCert OBJECT IDENTIFIER ::= {id-cmc 15}
	/// 
	///      GetCert ::= SEQUENCE {
	///           issuerName      GeneralName,
	///           serialNumber    INTEGER }
	/// </pre>
	/// </summary>
	public class GetCert : ASN1Object
	{
		private readonly GeneralName issuerName;
		private readonly BigInteger serialNumber;

		private GetCert(ASN1Sequence seq)
		{
			if (seq.size() != 2)
			{
				throw new IllegalArgumentException("incorrect sequence size");
			}
			this.issuerName = GeneralName.getInstance(seq.getObjectAt(0));
			this.serialNumber = ASN1Integer.getInstance(seq.getObjectAt(1)).getValue();
		}

		public GetCert(GeneralName issuerName, BigInteger serialNumber)
		{
			this.issuerName = issuerName;
			this.serialNumber = serialNumber;
		}

		public static GetCert getInstance(object o)
		{
			if (o is GetCert)
			{
				return (GetCert)o;
			}

			if (o != null)
			{
				return new GetCert(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public virtual GeneralName getIssuerName()
		{
			return issuerName;
		}

		public virtual BigInteger getSerialNumber()
		{
			return serialNumber;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(issuerName);
			v.add(new ASN1Integer(serialNumber));

			return new DERSequence(v);
		}
	}

}