using org.bouncycastle.asn1.x509;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cms
{
	
	/// <summary>
	/// From RFC 6211
	/// <pre>
	/// CMSAlgorithmProtection ::= SEQUENCE {
	///    digestAlgorithm         DigestAlgorithmIdentifier,
	///    signatureAlgorithm  [1] SignatureAlgorithmIdentifier OPTIONAL,
	///    macAlgorithm        [2] MessageAuthenticationCodeAlgorithm
	///                                     OPTIONAL
	/// }
	/// (WITH COMPONENTS { signatureAlgorithm PRESENT,
	///                    macAlgorithm ABSENT } |
	///  WITH COMPONENTS { signatureAlgorithm ABSENT,
	///                    macAlgorithm PRESENT })
	/// </pre>
	/// </summary>
	public class CMSAlgorithmProtection : ASN1Object
	{
		public const int SIGNATURE = 1;
		public const int MAC = 2;

		private readonly AlgorithmIdentifier digestAlgorithm;
		private readonly AlgorithmIdentifier signatureAlgorithm;
		private readonly AlgorithmIdentifier macAlgorithm;

		public CMSAlgorithmProtection(AlgorithmIdentifier digestAlgorithm, int type, AlgorithmIdentifier algorithmIdentifier)
		{
			if (digestAlgorithm == null || algorithmIdentifier == null)
			{
				throw new NullPointerException("AlgorithmIdentifiers cannot be null");
			}

			this.digestAlgorithm = digestAlgorithm;

			if (type == 1)
			{
				this.signatureAlgorithm = algorithmIdentifier;
				this.macAlgorithm = null;
			}
			else if (type == 2)
			{
				this.signatureAlgorithm = null;
				this.macAlgorithm = algorithmIdentifier;
			}
			else
			{
				throw new IllegalArgumentException("Unknown type: " + type);
			}
		}

		private CMSAlgorithmProtection(ASN1Sequence sequence)
		{
			if (sequence.size() != 2)
			{
				throw new IllegalArgumentException("Sequence wrong size: One of signatureAlgorithm or macAlgorithm must be present");
			}

			this.digestAlgorithm = AlgorithmIdentifier.getInstance(sequence.getObjectAt(0));

			ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(sequence.getObjectAt(1));
			if (tagged.getTagNo() == 1)
			{
				this.signatureAlgorithm = AlgorithmIdentifier.getInstance(tagged, false);
				this.macAlgorithm = null;
			}
			else if (tagged.getTagNo() == 2)
			{
				this.signatureAlgorithm = null;

				this.macAlgorithm = AlgorithmIdentifier.getInstance(tagged, false);
			}
			else
			{
				throw new IllegalArgumentException("Unknown tag found: " + tagged.getTagNo());
			}
		}

		public static CMSAlgorithmProtection getInstance(object obj)
		{
			if (obj is CMSAlgorithmProtection)
			{
				return (CMSAlgorithmProtection)obj;
			}
			else if (obj != null)
			{
				return new CMSAlgorithmProtection(ASN1Sequence.getInstance(obj));
			}

			return null;
		}


		public virtual AlgorithmIdentifier getDigestAlgorithm()
		{
			return digestAlgorithm;
		}

		public virtual AlgorithmIdentifier getMacAlgorithm()
		{
			return macAlgorithm;
		}

		public virtual AlgorithmIdentifier getSignatureAlgorithm()
		{
			return signatureAlgorithm;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(digestAlgorithm);
			if (signatureAlgorithm != null)
			{
				v.add(new DERTaggedObject(false, 1, signatureAlgorithm));
			}
			if (macAlgorithm != null)
			{
				v.add(new DERTaggedObject(false, 2, macAlgorithm));
			}

			return new DERSequence(v);
		}
	}

}