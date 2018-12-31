using org.bouncycastle.asn1.x509;

namespace org.bouncycastle.asn1.ocsp
{
	
	public class CertID : ASN1Object
	{
		internal AlgorithmIdentifier hashAlgorithm;
		internal ASN1OctetString issuerNameHash;
		internal ASN1OctetString issuerKeyHash;
		internal ASN1Integer serialNumber;

		public CertID(AlgorithmIdentifier hashAlgorithm, ASN1OctetString issuerNameHash, ASN1OctetString issuerKeyHash, ASN1Integer serialNumber)
		{
			this.hashAlgorithm = hashAlgorithm;
			this.issuerNameHash = issuerNameHash;
			this.issuerKeyHash = issuerKeyHash;
			this.serialNumber = serialNumber;
		}

		private CertID(ASN1Sequence seq)
		{
			hashAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
			issuerNameHash = (ASN1OctetString)seq.getObjectAt(1);
			issuerKeyHash = (ASN1OctetString)seq.getObjectAt(2);
			serialNumber = (ASN1Integer)seq.getObjectAt(3);
		}

		public static CertID getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public static CertID getInstance(object obj)
		{
			if (obj is CertID)
			{
				return (CertID)obj;
			}
			else if (obj != null)
			{
				return new CertID(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public virtual AlgorithmIdentifier getHashAlgorithm()
		{
			return hashAlgorithm;
		}

		public virtual ASN1OctetString getIssuerNameHash()
		{
			return issuerNameHash;
		}

		public virtual ASN1OctetString getIssuerKeyHash()
		{
			return issuerKeyHash;
		}

		public virtual ASN1Integer getSerialNumber()
		{
			return serialNumber;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// <pre>
		/// CertID          ::=     SEQUENCE {
		///     hashAlgorithm       AlgorithmIdentifier,
		///     issuerNameHash      OCTET STRING, -- Hash of Issuer's DN
		///     issuerKeyHash       OCTET STRING, -- Hash of Issuers public key
		///     serialNumber        CertificateSerialNumber }
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(hashAlgorithm);
			v.add(issuerNameHash);
			v.add(issuerKeyHash);
			v.add(serialNumber);

			return new DERSequence(v);
		}
	}

}