using BouncyCastle.Core.Port;

namespace org.bouncycastle.asn1.pkcs
{

	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using X509Name = org.bouncycastle.asn1.x509.X509Name;

	public class IssuerAndSerialNumber : ASN1Object
	{
		internal X500Name name;
		internal ASN1Integer certSerialNumber;

		public static IssuerAndSerialNumber getInstance(object obj)
		{
			if (obj is IssuerAndSerialNumber)
			{
				return (IssuerAndSerialNumber)obj;
			}
			else if (obj != null)
			{
				return new IssuerAndSerialNumber(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		private IssuerAndSerialNumber(ASN1Sequence seq)
		{
			this.name = X500Name.getInstance(seq.getObjectAt(0));
			this.certSerialNumber = (ASN1Integer)seq.getObjectAt(1);
		}

		public IssuerAndSerialNumber(X509Name name, BigInteger certSerialNumber)
		{
			this.name = X500Name.getInstance(name.toASN1Primitive());
			this.certSerialNumber = new ASN1Integer(certSerialNumber);
		}

		public IssuerAndSerialNumber(X509Name name, ASN1Integer certSerialNumber)
		{
			this.name = X500Name.getInstance(name.toASN1Primitive());
			this.certSerialNumber = certSerialNumber;
		}

		public IssuerAndSerialNumber(X500Name name, BigInteger certSerialNumber)
		{
			this.name = name;
			this.certSerialNumber = new ASN1Integer(certSerialNumber);
		}

		public virtual X500Name getName()
		{
			return name;
		}

		public virtual ASN1Integer getCertificateSerialNumber()
		{
			return certSerialNumber;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(name);
			v.add(certSerialNumber);

			return new DERSequence(v);
		}
	}

}