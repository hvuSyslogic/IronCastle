using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.ess
{
	using IssuerSerial = org.bouncycastle.asn1.x509.IssuerSerial;

	public class ESSCertID : ASN1Object
	{
		private ASN1OctetString certHash;

		private IssuerSerial issuerSerial;

		public static ESSCertID getInstance(object o)
		{
			if (o is ESSCertID)
			{
				return (ESSCertID)o;
			}
			else if (o != null)
			{
				return new ESSCertID(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		/// <summary>
		/// constructor
		/// </summary>
		private ESSCertID(ASN1Sequence seq)
		{
			if (seq.size() < 1 || seq.size() > 2)
			{
				throw new IllegalArgumentException("Bad sequence size: " + seq.size());
			}

			certHash = ASN1OctetString.getInstance(seq.getObjectAt(0));

			if (seq.size() > 1)
			{
				issuerSerial = IssuerSerial.getInstance(seq.getObjectAt(1));
			}
		}

		public ESSCertID(byte[] hash)
		{
			certHash = new DEROctetString(hash);
		}

		public ESSCertID(byte[] hash, IssuerSerial issuerSerial)
		{
			this.certHash = new DEROctetString(hash);
			this.issuerSerial = issuerSerial;
		}

		public virtual byte[] getCertHash()
		{
			return certHash.getOctets();
		}

		public virtual IssuerSerial getIssuerSerial()
		{
			return issuerSerial;
		}

		/// <summary>
		/// <pre>
		/// ESSCertID ::= SEQUENCE {
		///     certHash Hash, 
		///     issuerSerial IssuerSerial OPTIONAL }
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(certHash);

			if (issuerSerial != null)
			{
				v.add(issuerSerial);
			}

			return new DERSequence(v);
		}
	}

}