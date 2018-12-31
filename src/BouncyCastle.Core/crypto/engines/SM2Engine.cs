using System;
using BouncyCastle.Core.Port;
using org.bouncycastle.crypto.digests;
using org.bouncycastle.crypto.@params;
using org.bouncycastle.math.ec;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.engines
{

															
	/// <summary>
	/// SM2 public key encryption engine - based on https://tools.ietf.org/html/draft-shen-sm2-ecdsa-02.
	/// </summary>
	public class SM2Engine
	{
		private readonly Digest digest;

		private bool forEncryption;
		private ECKeyParameters ecKey;
		private ECDomainParameters ecParams;
		private int curveLength;
		private SecureRandom random;

		public SM2Engine() : this(new SM3Digest())
		{
		}

		public SM2Engine(Digest digest)
		{
			this.digest = digest;
		}

		public virtual void init(bool forEncryption, CipherParameters param)
		{
			this.forEncryption = forEncryption;

			if (forEncryption)
			{
				ParametersWithRandom rParam = (ParametersWithRandom)param;

				ecKey = (ECKeyParameters)rParam.getParameters();
				ecParams = ecKey.getParameters();

				ECPoint s = ((ECPublicKeyParameters)ecKey).getQ().multiply(ecParams.getH());
				if (s.isInfinity())
				{
					throw new IllegalArgumentException("invalid key: [h]Q at infinity");
				}

				random = rParam.getRandom();
			}
			else
			{
				ecKey = (ECKeyParameters)param;
				ecParams = ecKey.getParameters();
			}

			curveLength = (ecParams.getCurve().getFieldSize() + 7) / 8;
		}

		public virtual byte[] processBlock(byte[] @in, int inOff, int inLen)
		{
			if (forEncryption)
			{
				return encrypt(@in, inOff, inLen);
			}
			else
			{
				return decrypt(@in, inOff, inLen);
			}
		}

		public virtual ECMultiplier createBasePointMultiplier()
		{
			return new FixedPointCombMultiplier();
		}

		private byte[] encrypt(byte[] @in, int inOff, int inLen)
		{
			byte[] c2 = new byte[inLen];

			JavaSystem.arraycopy(@in, inOff, c2, 0, c2.Length);

			ECMultiplier multiplier = createBasePointMultiplier();

			byte[] c1;
			ECPoint kPB;
			do
			{
				BigInteger k = nextK();

				ECPoint c1P = multiplier.multiply(ecParams.getG(), k).normalize();

				c1 = c1P.getEncoded(false);

				kPB = ((ECPublicKeyParameters)ecKey).getQ().multiply(k).normalize();

				kdf(digest, kPB, c2);
			} while (notEncrypted(c2, @in, inOff));

			byte[] c3 = new byte[digest.getDigestSize()];

			addFieldElement(digest, kPB.getAffineXCoord());
			digest.update(@in, inOff, inLen);
			addFieldElement(digest, kPB.getAffineYCoord());

			digest.doFinal(c3, 0);

			return Arrays.concatenate(c1, c2, c3);
		}

		private byte[] decrypt(byte[] @in, int inOff, int inLen)
		{
			byte[] c1 = new byte[curveLength * 2 + 1];

			JavaSystem.arraycopy(@in, inOff, c1, 0, c1.Length);

			ECPoint c1P = ecParams.getCurve().decodePoint(c1);

			ECPoint s = c1P.multiply(ecParams.getH());
			if (s.isInfinity())
			{
				throw new InvalidCipherTextException("[h]C1 at infinity");
			}

			c1P = c1P.multiply(((ECPrivateKeyParameters)ecKey).getD()).normalize();

			byte[] c2 = new byte[inLen - c1.Length - digest.getDigestSize()];

			JavaSystem.arraycopy(@in, inOff + c1.Length, c2, 0, c2.Length);

			kdf(digest, c1P, c2);

			byte[] c3 = new byte[digest.getDigestSize()];

			addFieldElement(digest, c1P.getAffineXCoord());
			digest.update(c2, 0, c2.Length);
			addFieldElement(digest, c1P.getAffineYCoord());

			digest.doFinal(c3, 0);

			int check = 0;
			for (int i = 0; i != c3.Length; i++)
			{
				check |= c3[i] ^ @in[inOff + c1.Length + c2.Length + i];
			}

			Arrays.fill(c1, 0);
			Arrays.fill(c3, 0);

			if (check != 0)
			{
				Arrays.fill(c2, 0);
				throw new InvalidCipherTextException("invalid cipher text");
			}

			return c2;
		}

		private bool notEncrypted(byte[] encData, byte[] @in, int inOff)
		{
			for (int i = 0; i != encData.Length; i++)
			{
				if (encData[i] != @in[inOff])
				{
					return false;
				}
			}

			return true;
		}

		private void kdf(Digest digest, ECPoint c1, byte[] encData)
		{
			int digestSize = digest.getDigestSize();
			byte[] buf = new byte[Math.Max(4, digestSize)];
			int off = 0;

			Memoable memo = null;
			Memoable copy = null;

			if (digest is Memoable)
			{
				addFieldElement(digest, c1.getAffineXCoord());
				addFieldElement(digest, c1.getAffineYCoord());
				memo = (Memoable)digest;
				copy = memo.copy();
			}

			int ct = 0;

			while (off < encData.Length)
			{
				if (memo != null)
				{
					memo.reset(copy);
				}
				else
				{
					addFieldElement(digest, c1.getAffineXCoord());
					addFieldElement(digest, c1.getAffineYCoord());
				}

				Pack.intToBigEndian(++ct, buf, 0);
				digest.update(buf, 0, 4);
				digest.doFinal(buf, 0);

				int xorLen = Math.Min(digestSize, encData.Length - off);
				xor(encData, buf, off, xorLen);
				off += xorLen;
			}
		}

		private void xor(byte[] data, byte[] kdfOut, int dOff, int dRemaining)
		{
			for (int i = 0; i != dRemaining; i++)
			{
				data[dOff + i] ^= kdfOut[i];
			}
		}

		private BigInteger nextK()
		{
			int qBitLength = ecParams.getN().bitLength();

			BigInteger k;
			do
			{
				k = BigIntegers.createRandomBigInteger(qBitLength, random);
			} while (k.Equals(ECConstants_Fields.ZERO) || k.compareTo(ecParams.getN()) >= 0);

			return k;
		}

		private void addFieldElement(Digest digest, ECFieldElement v)
		{
			byte[] p = BigIntegers.asUnsignedByteArray(curveLength, v.toBigInteger());

			digest.update(p, 0, p.Length);
		}
	}

}