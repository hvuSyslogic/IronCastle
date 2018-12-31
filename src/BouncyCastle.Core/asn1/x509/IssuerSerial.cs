using BouncyCastle.Core.Port;
using org.bouncycastle.asn1.x500;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.x509
{

	
	public class IssuerSerial : ASN1Object
	{
		internal GeneralNames issuer;
		internal ASN1Integer serial;
		internal DERBitString issuerUID;

		public static IssuerSerial getInstance(object obj)
		{
			if (obj is IssuerSerial)
			{
				return (IssuerSerial)obj;
			}

			if (obj != null)
			{
				return new IssuerSerial(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public static IssuerSerial getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		private IssuerSerial(ASN1Sequence seq)
		{
			if (seq.size() != 2 && seq.size() != 3)
			{
				throw new IllegalArgumentException("Bad sequence size: " + seq.size());
			}

			issuer = GeneralNames.getInstance(seq.getObjectAt(0));
			serial = ASN1Integer.getInstance(seq.getObjectAt(1));

			if (seq.size() == 3)
			{
				issuerUID = DERBitString.getInstance(seq.getObjectAt(2));
			}
		}

		public IssuerSerial(X500Name issuer, BigInteger serial) : this(new GeneralNames(new GeneralName(issuer)), new ASN1Integer(serial))
		{
		}

		public IssuerSerial(GeneralNames issuer, BigInteger serial) : this(issuer, new ASN1Integer(serial))
		{
		}

		public IssuerSerial(GeneralNames issuer, ASN1Integer serial)
		{
			this.issuer = issuer;
			this.serial = serial;
		}

		public virtual GeneralNames getIssuer()
		{
			return issuer;
		}

		public virtual ASN1Integer getSerial()
		{
			return serial;
		}

		public virtual DERBitString getIssuerUID()
		{
			return issuerUID;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// <pre>
		///  IssuerSerial  ::=  SEQUENCE {
		///       issuer         GeneralNames,
		///       serial         CertificateSerialNumber,
		///       issuerUID      UniqueIdentifier OPTIONAL
		///  }
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(issuer);
			v.add(serial);

			if (issuerUID != null)
			{
				v.add(issuerUID);
			}

			return new DERSequence(v);
		}
	}

}