using BouncyCastle.Core.Port;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.cryptopro
{


	public class ECGOST3410ParamSetParameters : ASN1Object
	{
		internal ASN1Integer p, q, a, b, x, y;

		public static ECGOST3410ParamSetParameters getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public static ECGOST3410ParamSetParameters getInstance(object obj)
		{
			if (obj == null || obj is ECGOST3410ParamSetParameters)
			{
				return (ECGOST3410ParamSetParameters)obj;
			}

			if (obj is ASN1Sequence)
			{
				return new ECGOST3410ParamSetParameters((ASN1Sequence)obj);
			}

			throw new IllegalArgumentException("Invalid GOST3410Parameter: " + obj.GetType().getName());
		}

		public ECGOST3410ParamSetParameters(BigInteger a, BigInteger b, BigInteger p, BigInteger q, int x, BigInteger y)
		{
			this.a = new ASN1Integer(a);
			this.b = new ASN1Integer(b);
			this.p = new ASN1Integer(p);
			this.q = new ASN1Integer(q);
			this.x = new ASN1Integer(x);
			this.y = new ASN1Integer(y);
		}

		public ECGOST3410ParamSetParameters(ASN1Sequence seq)
		{
			Enumeration e = seq.getObjects();

			a = (ASN1Integer)e.nextElement();
			b = (ASN1Integer)e.nextElement();
			p = (ASN1Integer)e.nextElement();
			q = (ASN1Integer)e.nextElement();
			x = (ASN1Integer)e.nextElement();
			y = (ASN1Integer)e.nextElement();
		}

		public virtual BigInteger getP()
		{
			return p.getPositiveValue();
		}

		public virtual BigInteger getQ()
		{
			return q.getPositiveValue();
		}

		public virtual BigInteger getA()
		{
			return a.getPositiveValue();
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(a);
			v.add(b);
			v.add(p);
			v.add(q);
			v.add(x);
			v.add(y);

			return new DERSequence(v);
		}
	}

}