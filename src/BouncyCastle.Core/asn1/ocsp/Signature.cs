using org.bouncycastle.asn1.x509;

namespace org.bouncycastle.asn1.ocsp
{
	
	public class Signature : ASN1Object
	{
		internal AlgorithmIdentifier signatureAlgorithm;
		internal DERBitString signature;
		internal ASN1Sequence certs;

		public Signature(AlgorithmIdentifier signatureAlgorithm, DERBitString signature)
		{
			this.signatureAlgorithm = signatureAlgorithm;
			this.signature = signature;
		}

		public Signature(AlgorithmIdentifier signatureAlgorithm, DERBitString signature, ASN1Sequence certs)
		{
			this.signatureAlgorithm = signatureAlgorithm;
			this.signature = signature;
			this.certs = certs;
		}

		private Signature(ASN1Sequence seq)
		{
			signatureAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
			signature = (DERBitString)seq.getObjectAt(1);

			if (seq.size() == 3)
			{
				certs = ASN1Sequence.getInstance((ASN1TaggedObject)seq.getObjectAt(2), true);
			}
		}

		public static Signature getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public static Signature getInstance(object obj)
		{
			if (obj is Signature)
			{
				return (Signature)obj;
			}
			else if (obj != null)
			{
				return new Signature(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public virtual AlgorithmIdentifier getSignatureAlgorithm()
		{
			return signatureAlgorithm;
		}

		public virtual DERBitString getSignature()
		{
			return signature;
		}

		public virtual ASN1Sequence getCerts()
		{
			return certs;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// <pre>
		/// Signature       ::=     SEQUENCE {
		///     signatureAlgorithm      AlgorithmIdentifier,
		///     signature               BIT STRING,
		///     certs               [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL}
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(signatureAlgorithm);
			v.add(signature);

			if (certs != null)
			{
				v.add(new DERTaggedObject(true, 0, certs));
			}

			return new DERSequence(v);
		}
	}

}