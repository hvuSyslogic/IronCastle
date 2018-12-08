using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.oiw
{


	public class ElGamalParameter : ASN1Object
	{
		internal ASN1Integer p, g;

		public ElGamalParameter(BigInteger p, BigInteger g)
		{
			this.p = new ASN1Integer(p);
			this.g = new ASN1Integer(g);
		}

		private ElGamalParameter(ASN1Sequence seq)
		{
			Enumeration e = seq.getObjects();

			p = (ASN1Integer)e.nextElement();
			g = (ASN1Integer)e.nextElement();
		}

		public static ElGamalParameter getInstance(object o)
		{
			if (o is ElGamalParameter)
			{
				return (ElGamalParameter)o;
			}
			else if (o != null)
			{
				return new ElGamalParameter(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public virtual BigInteger getP()
		{
			return p.getPositiveValue();
		}

		public virtual BigInteger getG()
		{
			return g.getPositiveValue();
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(p);
			v.add(g);

			return new DERSequence(v);
		}
	}

}