using org.bouncycastle.Port.java.util;
using org.bouncycastle.util;

namespace org.bouncycastle.asn1.x509
{

	
	/// <summary>
	/// The DigestInfo object.
	/// <pre>
	/// DigestInfo::=SEQUENCE{
	///          digestAlgorithm  AlgorithmIdentifier,
	///          digest OCTET STRING }
	/// </pre>
	/// </summary>
	public class DigestInfo : ASN1Object
	{
		private byte[] digest;
		private AlgorithmIdentifier algId;

		public static DigestInfo getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public static DigestInfo getInstance(object obj)
		{
			if (obj is DigestInfo)
			{
				return (DigestInfo)obj;
			}
			else if (obj != null)
			{
				return new DigestInfo(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public DigestInfo(AlgorithmIdentifier algId, byte[] digest)
		{
			this.digest = Arrays.clone(digest);
			this.algId = algId;
		}

		public DigestInfo(ASN1Sequence obj)
		{
			Enumeration e = obj.getObjects();

			algId = AlgorithmIdentifier.getInstance(e.nextElement());
			digest = ASN1OctetString.getInstance(e.nextElement()).getOctets();
		}

		public virtual AlgorithmIdentifier getAlgorithmId()
		{
			return algId;
		}

		public virtual byte[] getDigest()
		{
			return Arrays.clone(digest);
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(algId);
			v.add(new DEROctetString(digest));

			return new DERSequence(v);
		}
	}

}