using System;
using BouncyCastle.Core.Port;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.signers
{

		
	public class PlainDSAEncoding : DSAEncoding
	{
		public static readonly PlainDSAEncoding INSTANCE = new PlainDSAEncoding();

		public virtual byte[] encode(BigInteger n, BigInteger r, BigInteger s)
		{
			int valueLength = BigIntegers.getUnsignedByteLength(n);
			byte[] result = new byte[valueLength * 2];
			encodeValue(n, r, result, 0, valueLength);
			encodeValue(n, s, result, valueLength, valueLength);
			return result;
		}

		public virtual BigInteger[] decode(BigInteger n, byte[] encoding)
		{
			int valueLength = BigIntegers.getUnsignedByteLength(n);
			if (encoding.Length != valueLength * 2)
			{
				throw new IllegalArgumentException("Encoding has incorrect length");
			}

			return new BigInteger[] {decodeValue(n, encoding, 0, valueLength), decodeValue(n, encoding, valueLength, valueLength)};
		}

		public virtual BigInteger checkValue(BigInteger n, BigInteger x)
		{
			if (x.signum() < 0 || x.compareTo(n) >= 0)
			{
				throw new IllegalArgumentException("Value out of range");
			}

			return x;
		}

		public virtual BigInteger decodeValue(BigInteger n, byte[] buf, int off, int len)
		{
			byte[] bs = Arrays.copyOfRange(buf, off, off + len);
			return checkValue(n, new BigInteger(1, bs));
		}

		private void encodeValue(BigInteger n, BigInteger x, byte[] buf, int off, int len)
		{
			byte[] bs = checkValue(n, x).toByteArray();
			int bsOff = Math.Max(0, bs.Length - len);
			int bsLen = bs.Length - bsOff;

			int pos = len - bsLen;
			Arrays.fill(buf, off, off + pos, 0);
			JavaSystem.arraycopy(bs, bsOff, buf, off + pos, bsLen);
		}
	}

}