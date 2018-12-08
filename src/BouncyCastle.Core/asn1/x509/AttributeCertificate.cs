using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.x509
{

	public class AttributeCertificate : ASN1Object
	{
		internal AttributeCertificateInfo acinfo;
		internal AlgorithmIdentifier signatureAlgorithm;
		internal DERBitString signatureValue;

		/// <param name="obj"> </param>
		/// <returns> an AttributeCertificate object </returns>
		public static AttributeCertificate getInstance(object obj)
		{
			if (obj is AttributeCertificate)
			{
				return (AttributeCertificate)obj;
			}
			else if (obj != null)
			{
				return new AttributeCertificate(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public AttributeCertificate(AttributeCertificateInfo acinfo, AlgorithmIdentifier signatureAlgorithm, DERBitString signatureValue)
		{
			this.acinfo = acinfo;
			this.signatureAlgorithm = signatureAlgorithm;
			this.signatureValue = signatureValue;
		}

		/// @deprecated use getInstance() method. 
		public AttributeCertificate(ASN1Sequence seq)
		{
			if (seq.size() != 3)
			{
				throw new IllegalArgumentException("Bad sequence size: " + seq.size());
			}

			this.acinfo = AttributeCertificateInfo.getInstance(seq.getObjectAt(0));
			this.signatureAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
			this.signatureValue = DERBitString.getInstance(seq.getObjectAt(2));
		}

		public virtual AttributeCertificateInfo getAcinfo()
		{
			return acinfo;
		}

		public virtual AlgorithmIdentifier getSignatureAlgorithm()
		{
			return signatureAlgorithm;
		}

		public virtual DERBitString getSignatureValue()
		{
			return signatureValue;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// <pre>
		///  AttributeCertificate ::= SEQUENCE {
		///       acinfo               AttributeCertificateInfo,
		///       signatureAlgorithm   AlgorithmIdentifier,
		///       signatureValue       BIT STRING
		///  }
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(acinfo);
			v.add(signatureAlgorithm);
			v.add(signatureValue);

			return new DERSequence(v);
		}
	}

}