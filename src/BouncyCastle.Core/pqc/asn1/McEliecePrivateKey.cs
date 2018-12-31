using BouncyCastle.Core.Port;
using org.bouncycastle.asn1;
using org.bouncycastle.pqc.math.linearalgebra;

namespace org.bouncycastle.pqc.asn1
{

												
	public class McEliecePrivateKey : ASN1Object
	{
		private int n;
		private int k;
		private byte[] encField;
		private byte[] encGp;
		private byte[] encSInv;
		private byte[] encP1;
		private byte[] encP2;

		public McEliecePrivateKey(int n, int k, GF2mField field, PolynomialGF2mSmallM goppaPoly, Permutation p1, Permutation p2, GF2Matrix sInv)
		{
			this.n = n;
			this.k = k;
			this.encField = field.getEncoded();
			this.encGp = goppaPoly.getEncoded();
			this.encSInv = sInv.getEncoded();
			this.encP1 = p1.getEncoded();
			this.encP2 = p2.getEncoded();
		}

		public static McEliecePrivateKey getInstance(object o)
		{
			if (o is McEliecePrivateKey)
			{
				return (McEliecePrivateKey)o;
			}
			else if (o != null)
			{
				return new McEliecePrivateKey(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		private McEliecePrivateKey(ASN1Sequence seq)
		{
			BigInteger bigN = ((ASN1Integer)seq.getObjectAt(0)).getValue();
			n = bigN.intValue();

			BigInteger bigK = ((ASN1Integer)seq.getObjectAt(1)).getValue();
			k = bigK.intValue();

			encField = ((ASN1OctetString)seq.getObjectAt(2)).getOctets();

			encGp = ((ASN1OctetString)seq.getObjectAt(3)).getOctets();

			encP1 = ((ASN1OctetString)seq.getObjectAt(4)).getOctets();

			encP2 = ((ASN1OctetString)seq.getObjectAt(5)).getOctets();

			encSInv = ((ASN1OctetString)seq.getObjectAt(6)).getOctets();
		}

		public virtual int getN()
		{
			return n;
		}

		public virtual int getK()
		{
			return k;
		}

		public virtual GF2mField getField()
		{
			return new GF2mField(encField);
		}

		public virtual PolynomialGF2mSmallM getGoppaPoly()
		{
			return new PolynomialGF2mSmallM(this.getField(), encGp);
		}

		public virtual GF2Matrix getSInv()
		{
			return new GF2Matrix(encSInv);
		}

		public virtual Permutation getP1()
		{
			return new Permutation(encP1);
		}

		public virtual Permutation getP2()
		{
			return new Permutation(encP2);
		}


		public override ASN1Primitive toASN1Primitive()
		{

			ASN1EncodableVector v = new ASN1EncodableVector();

			// encode <n>
			v.add(new ASN1Integer(n));

			// encode <k>
			v.add(new ASN1Integer(k));

			// encode <fieldPoly>
			v.add(new DEROctetString(encField));

			// encode <goppaPoly>
			v.add(new DEROctetString(encGp));

			// encode <p1>
			v.add(new DEROctetString(encP1));

			// encode <p2>
			v.add(new DEROctetString(encP2));

			// encode <sInv>
			v.add(new DEROctetString(encSInv));

			return new DERSequence(v);
		}
	}

}