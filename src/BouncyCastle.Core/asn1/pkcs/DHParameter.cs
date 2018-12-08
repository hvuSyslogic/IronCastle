using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.pkcs
{


	public class DHParameter : ASN1Object
	{
		internal ASN1Integer p, g, l;

		public DHParameter(BigInteger p, BigInteger g, int l)
		{
			this.p = new ASN1Integer(p);
			this.g = new ASN1Integer(g);

			if (l != 0)
			{
				this.l = new ASN1Integer(l);
			}
			else
			{
				this.l = null;
			}
		}

		public static DHParameter getInstance(object obj)
		{
			if (obj is DHParameter)
			{
				return (DHParameter)obj;
			}

			if (obj != null)
			{
				return new DHParameter(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		private DHParameter(ASN1Sequence seq)
		{
			Enumeration e = seq.getObjects();

			p = ASN1Integer.getInstance(e.nextElement());
			g = ASN1Integer.getInstance(e.nextElement());

			if (e.hasMoreElements())
			{
				l = (ASN1Integer)e.nextElement();
			}
			else
			{
				l = null;
			}
		}

		public virtual BigInteger getP()
		{
			return p.getPositiveValue();
		}

		public virtual BigInteger getG()
		{
			return g.getPositiveValue();
		}

		public virtual BigInteger getL()
		{
			if (l == null)
			{
				return null;
			}

			return l.getPositiveValue();
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(p);
			v.add(g);

			if (this.getL() != null)
			{
				v.add(l);
			}

			return new DERSequence(v);
		}
	}

}