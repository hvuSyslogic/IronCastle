using BouncyCastle.Core.Port;
using org.bouncycastle.asn1;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.signers
{

							
	public class StandardDSAEncoding : DSAEncoding
	{
		public static readonly StandardDSAEncoding INSTANCE = new StandardDSAEncoding();

		public virtual byte[] encode(BigInteger n, BigInteger r, BigInteger s)
		{
			ASN1EncodableVector v = new ASN1EncodableVector();
			encodeValue(n, v, r);
			encodeValue(n, v, s);
			return (new DERSequence(v)).getEncoded(ASN1Encoding_Fields.DER);
		}

		public virtual BigInteger[] decode(BigInteger n, byte[] encoding)
		{
			ASN1Sequence seq = (ASN1Sequence)ASN1Primitive.fromByteArray(encoding);
			if (seq.size() == 2)
			{
				BigInteger r = decodeValue(n, seq, 0);
				BigInteger s = decodeValue(n, seq, 1);

				byte[] expectedEncoding = encode(n, r, s);
				if (Arrays.areEqual(expectedEncoding, encoding))
				{
					return new BigInteger[]{r, s};
				}
			}

			throw new IllegalArgumentException("Malformed signature");
		}

		public virtual BigInteger checkValue(BigInteger n, BigInteger x)
		{
			if (x.signum() < 0 || (null != n && x.compareTo(n) >= 0))
			{
				throw new IllegalArgumentException("Value out of range");
			}

			return x;
		}

		public virtual BigInteger decodeValue(BigInteger n, ASN1Sequence s, int pos)
		{
			return checkValue(n, ((ASN1Integer)s.getObjectAt(pos)).getValue());
		}

		public virtual void encodeValue(BigInteger n, ASN1EncodableVector v, BigInteger x)
		{
			v.add(new ASN1Integer(checkValue(n, x)));
		}
	}

}