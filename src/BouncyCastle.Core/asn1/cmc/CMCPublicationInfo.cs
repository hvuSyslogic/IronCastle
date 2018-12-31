using org.bouncycastle.asn1.crmf;
using org.bouncycastle.asn1.x509;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.asn1.cmc
{
			
	/// <summary>
	/// <pre>
	///      CMCPublicationInfo ::= SEQUENCE {
	///           hashAlg                      AlgorithmIdentifier,
	///           certHashes                   SEQUENCE OF OCTET STRING,
	///           pubInfo                      PKIPublicationInfo
	/// }
	/// 
	/// </pre>
	/// </summary>
	public class CMCPublicationInfo : ASN1Object
	{
		private readonly AlgorithmIdentifier hashAlg;
		private readonly ASN1Sequence certHashes;
		private readonly PKIPublicationInfo pubInfo;

		public CMCPublicationInfo(AlgorithmIdentifier hashAlg, byte[][] anchorHashes, PKIPublicationInfo pubInfo)
		{
			this.hashAlg = hashAlg;

			ASN1EncodableVector v = new ASN1EncodableVector();
			for (int i = 0; i != anchorHashes.Length; i++)
			{
				 v.add(new DEROctetString(Arrays.clone(anchorHashes[i])));
			}
			this.certHashes = new DERSequence(v);

			this.pubInfo = pubInfo;
		}

		private CMCPublicationInfo(ASN1Sequence seq)
		{
			if (seq.size() != 3)
			{
				throw new IllegalArgumentException("incorrect sequence size");
			}
			this.hashAlg = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
			this.certHashes = ASN1Sequence.getInstance(seq.getObjectAt(1));
			this.pubInfo = PKIPublicationInfo.getInstance(seq.getObjectAt(2));
		}

		public static CMCPublicationInfo getInstance(object o)
		{
			if (o is CMCPublicationInfo)
			{
				return (CMCPublicationInfo)o;
			}

			if (o != null)
			{
				return new CMCPublicationInfo(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public virtual AlgorithmIdentifier getHashAlg()
		{
			return hashAlg;
		}

		public virtual byte[][] getCertHashes()
		{
			byte[][] hashes = new byte[certHashes.size()][];

			for (int i = 0; i != hashes.Length; i++)
			{
				hashes[i] = Arrays.clone(ASN1OctetString.getInstance(certHashes.getObjectAt(i)).getOctets());
			}

			return hashes;
		}

		public virtual PKIPublicationInfo getPubInfo()
		{
			return pubInfo;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(hashAlg);
			v.add(certHashes);
			v.add(pubInfo);

			return new DERSequence(v);
		}
	}

}