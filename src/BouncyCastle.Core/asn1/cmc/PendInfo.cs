using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.asn1.cmc
{
	
	/// <summary>
	/// <pre>
	/// PendInfo ::= SEQUENCE {
	///    pendToken        OCTET STRING,
	///    pendTime         GeneralizedTime
	/// }
	/// </pre>
	/// </summary>
	public class PendInfo : ASN1Object
	{
		private readonly byte[] pendToken;
		private readonly ASN1GeneralizedTime pendTime;

		public PendInfo(byte[] pendToken, ASN1GeneralizedTime pendTime)
		{
			this.pendToken = Arrays.clone(pendToken);
			this.pendTime = pendTime;
		}

		private PendInfo(ASN1Sequence seq)
		{
			if (seq.size() != 2)
			{
				throw new IllegalArgumentException("incorrect sequence size");
			}
			this.pendToken = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(0)).getOctets());
			this.pendTime = ASN1GeneralizedTime.getInstance(seq.getObjectAt(1));
		}

		public static PendInfo getInstance(object o)
		{
			if (o is PendInfo)
			{
				return (PendInfo)o;
			}

			if (o != null)
			{
				return new PendInfo(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(new DEROctetString(pendToken));
			v.add(pendTime);

			return new DERSequence(v);
		}

		public virtual byte[] getPendToken()
		{
			return Arrays.clone(pendToken);
		}

		public virtual ASN1GeneralizedTime getPendTime()
		{
			return pendTime;
		}
	}

}