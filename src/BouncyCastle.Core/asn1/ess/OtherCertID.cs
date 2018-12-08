using org.bouncycastle.asn1.oiw;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.ess
{
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using DigestInfo = org.bouncycastle.asn1.x509.DigestInfo;
	using IssuerSerial = org.bouncycastle.asn1.x509.IssuerSerial;

	public class OtherCertID : ASN1Object
	{
		private ASN1Encodable otherCertHash;
		private IssuerSerial issuerSerial;

		public static OtherCertID getInstance(object o)
		{
			if (o is OtherCertID)
			{
				return (OtherCertID) o;
			}
			else if (o != null)
			{
				return new OtherCertID(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		/// <summary>
		/// constructor
		/// </summary>
		private OtherCertID(ASN1Sequence seq)
		{
			if (seq.size() < 1 || seq.size() > 2)
			{
				throw new IllegalArgumentException("Bad sequence size: " + seq.size());
			}

			if (seq.getObjectAt(0).toASN1Primitive() is ASN1OctetString)
			{
				otherCertHash = ASN1OctetString.getInstance(seq.getObjectAt(0));
			}
			else
			{
				otherCertHash = DigestInfo.getInstance(seq.getObjectAt(0));

			}

			if (seq.size() > 1)
			{
				issuerSerial = IssuerSerial.getInstance(seq.getObjectAt(1));
			}
		}

		public OtherCertID(AlgorithmIdentifier algId, byte[] digest)
		{
			this.otherCertHash = new DigestInfo(algId, digest);
		}

		public OtherCertID(AlgorithmIdentifier algId, byte[] digest, IssuerSerial issuerSerial)
		{
			this.otherCertHash = new DigestInfo(algId, digest);
			this.issuerSerial = issuerSerial;
		}

		public virtual AlgorithmIdentifier getAlgorithmHash()
		{
			if (otherCertHash.toASN1Primitive() is ASN1OctetString)
			{
				// SHA-1
				return new AlgorithmIdentifier(OIWObjectIdentifiers_Fields.idSHA1);
			}
			else
			{
				return DigestInfo.getInstance(otherCertHash).getAlgorithmId();
			}
		}

		public virtual byte[] getCertHash()
		{
			if (otherCertHash.toASN1Primitive() is ASN1OctetString)
			{
				// SHA-1
				return ((ASN1OctetString)otherCertHash.toASN1Primitive()).getOctets();
			}
			else
			{
				return DigestInfo.getInstance(otherCertHash).getDigest();
			}
		}

		public virtual IssuerSerial getIssuerSerial()
		{
			return issuerSerial;
		}

		/// <summary>
		/// <pre>
		/// OtherCertID ::= SEQUENCE {
		///     otherCertHash    OtherHash,
		///     issuerSerial     IssuerSerial OPTIONAL }
		/// 
		/// OtherHash ::= CHOICE {
		///     sha1Hash     OCTET STRING,
		///     otherHash    OtherHashAlgAndValue }
		/// 
		/// OtherHashAlgAndValue ::= SEQUENCE {
		///     hashAlgorithm    AlgorithmIdentifier,
		///     hashValue        OCTET STRING }
		/// 
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(otherCertHash);

			if (issuerSerial != null)
			{
				v.add(issuerSerial);
			}

			return new DERSequence(v);
		}
	}

}