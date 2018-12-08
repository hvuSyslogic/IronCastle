using BouncyCastle.Core.Port;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.cryptopro
{


	public class GOST3410ParamSetParameters : ASN1Object
	{
		internal int keySize;
		internal ASN1Integer p, q, a;

		public static GOST3410ParamSetParameters getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public static GOST3410ParamSetParameters getInstance(object obj)
		{
			if (obj == null || obj is GOST3410ParamSetParameters)
			{
				return (GOST3410ParamSetParameters)obj;
			}

			if (obj is ASN1Sequence)
			{
				return new GOST3410ParamSetParameters((ASN1Sequence)obj);
			}

			throw new IllegalArgumentException("Invalid GOST3410Parameter: " + obj.GetType().getName());
		}

		public GOST3410ParamSetParameters(int keySize, BigInteger p, BigInteger q, BigInteger a)
		{
			this.keySize = keySize;
			this.p = new ASN1Integer(p);
			this.q = new ASN1Integer(q);
			this.a = new ASN1Integer(a);
		}

		public GOST3410ParamSetParameters(ASN1Sequence seq)
		{
			Enumeration e = seq.getObjects();

			keySize = ((ASN1Integer)e.nextElement()).getValue().intValue();
			p = (ASN1Integer)e.nextElement();
			q = (ASN1Integer)e.nextElement();
			a = (ASN1Integer)e.nextElement();
		}

		/// @deprecated use getKeySize 
		public virtual int getLKeySize()
		{
			return keySize;
		}

		public virtual int getKeySize()
		{
			return keySize;
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

			v.add(new ASN1Integer(keySize));
			v.add(p);
			v.add(q);
			v.add(a);

			return new DERSequence(v);
		}
	}

}