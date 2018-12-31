using BouncyCastle.Core.Port;
using org.bouncycastle.asn1;
using org.bouncycastle.pqc.math.linearalgebra;

namespace org.bouncycastle.pqc.asn1
{

									
	public class McEliecePublicKey : ASN1Object
	{
		private readonly int n;
		private readonly int t;
		private readonly GF2Matrix g;

		public McEliecePublicKey(int n, int t, GF2Matrix g)
		{
			this.n = n;
			this.t = t;
			this.g = new GF2Matrix(g);
		}

		private McEliecePublicKey(ASN1Sequence seq)
		{
			BigInteger bigN = ((ASN1Integer)seq.getObjectAt(0)).getValue();
			n = bigN.intValue();

			BigInteger bigT = ((ASN1Integer)seq.getObjectAt(1)).getValue();
			t = bigT.intValue();

			g = new GF2Matrix(((ASN1OctetString)seq.getObjectAt(2)).getOctets());
		}

		public virtual int getN()
		{
			return n;
		}

		public virtual int getT()
		{
			return t;
		}

		public virtual GF2Matrix getG()
		{
			return new GF2Matrix(g);
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			// encode <n>
			v.add(new ASN1Integer(n));

			// encode <t>
			v.add(new ASN1Integer(t));

			// encode <matrixG>
			v.add(new DEROctetString(g.getEncoded()));

			return new DERSequence(v);
		}

		public static McEliecePublicKey getInstance(object o)
		{
			if (o is McEliecePublicKey)
			{
				return (McEliecePublicKey)o;
			}
			else if (o != null)
			{
				return new McEliecePublicKey(ASN1Sequence.getInstance(o));
			}

			return null;
		}
	}

}