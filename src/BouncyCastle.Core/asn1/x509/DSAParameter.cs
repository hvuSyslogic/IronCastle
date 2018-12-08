using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.x509
{


	public class DSAParameter : ASN1Object
	{
		internal ASN1Integer p, q, g;

		public static DSAParameter getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public static DSAParameter getInstance(object obj)
		{
			if (obj is DSAParameter)
			{
				return (DSAParameter)obj;
			}

			if (obj != null)
			{
				return new DSAParameter(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public DSAParameter(BigInteger p, BigInteger q, BigInteger g)
		{
			this.p = new ASN1Integer(p);
			this.q = new ASN1Integer(q);
			this.g = new ASN1Integer(g);
		}

		private DSAParameter(ASN1Sequence seq)
		{
			if (seq.size() != 3)
			{
				throw new IllegalArgumentException("Bad sequence size: " + seq.size());
			}

			Enumeration e = seq.getObjects();

			p = ASN1Integer.getInstance(e.nextElement());
			q = ASN1Integer.getInstance(e.nextElement());
			g = ASN1Integer.getInstance(e.nextElement());
		}

		public virtual BigInteger getP()
		{
			return p.getPositiveValue();
		}

		public virtual BigInteger getQ()
		{
			return q.getPositiveValue();
		}

		public virtual BigInteger getG()
		{
			return g.getPositiveValue();
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(p);
			v.add(q);
			v.add(g);

			return new DERSequence(v);
		}
	}

}