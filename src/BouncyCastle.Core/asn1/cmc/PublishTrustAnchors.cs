using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cmc
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// <pre>
	/// 
	/// PublishTrustAnchors ::= SEQUENCE {
	///     seqNumber      INTEGER,
	///     hashAlgorithm  AlgorithmIdentifier,
	///     anchorHashes     SEQUENCE OF OCTET STRING
	/// }
	/// </pre>
	/// </summary>
	public class PublishTrustAnchors : ASN1Object
	{
		private readonly ASN1Integer seqNumber;
		private readonly AlgorithmIdentifier hashAlgorithm;
		private readonly ASN1Sequence anchorHashes;

		public PublishTrustAnchors(BigInteger seqNumber, AlgorithmIdentifier hashAlgorithm, byte[][] anchorHashes)
		{
			this.seqNumber = new ASN1Integer(seqNumber);
			this.hashAlgorithm = hashAlgorithm;

			ASN1EncodableVector v = new ASN1EncodableVector();
			for (int i = 0; i != anchorHashes.Length; i++)
			{
				 v.add(new DEROctetString(Arrays.clone(anchorHashes[i])));
			}
			this.anchorHashes = new DERSequence(v);
		}

		private PublishTrustAnchors(ASN1Sequence seq)
		{
			if (seq.size() != 3)
			{
				throw new IllegalArgumentException("incorrect sequence size");
			}
			this.seqNumber = ASN1Integer.getInstance(seq.getObjectAt(0));
			this.hashAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
			this.anchorHashes = ASN1Sequence.getInstance(seq.getObjectAt(2));
		}

		public static PublishTrustAnchors getInstance(object o)
		{
			if (o is PublishTrustAnchors)
			{
				return (PublishTrustAnchors)o;
			}

			if (o != null)
			{
				return new PublishTrustAnchors(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public virtual BigInteger getSeqNumber()
		{
			return seqNumber.getValue();
		}

		public virtual AlgorithmIdentifier getHashAlgorithm()
		{
			return hashAlgorithm;
		}

		public virtual byte[][] getAnchorHashes()
		{
			byte[][] hashes = new byte[anchorHashes.size()][];

			for (int i = 0; i != hashes.Length; i++)
			{
				hashes[i] = Arrays.clone(ASN1OctetString.getInstance(anchorHashes.getObjectAt(i)).getOctets());
			}

			return hashes;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(seqNumber);
			v.add(hashAlgorithm);
			v.add(anchorHashes);

			return new DERSequence(v);
		}
	}

}