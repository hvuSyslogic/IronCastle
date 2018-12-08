using System;
using BouncyCastle.Core.Port;
using org.bouncycastle.Port;

namespace org.bouncycastle.crypto.agreement.srp
{

	using BigIntegers = org.bouncycastle.util.BigIntegers;

	public class SRP6Util
	{
		private static BigInteger ZERO = BigInteger.valueOf(0);
		private static BigInteger ONE = BigInteger.valueOf(1);

		public static BigInteger calculateK(Digest digest, BigInteger N, BigInteger g)
		{
			return hashPaddedPair(digest, N, N, g);
		}

		public static BigInteger calculateU(Digest digest, BigInteger N, BigInteger A, BigInteger B)
		{
			return hashPaddedPair(digest, N, A, B);
		}

		public static BigInteger calculateX(Digest digest, BigInteger N, byte[] salt, byte[] identity, byte[] password)
		{
			byte[] output = new byte[digest.getDigestSize()];

			digest.update(identity, 0, identity.Length);
			digest.update((byte)':');
			digest.update(password, 0, password.Length);
			digest.doFinal(output, 0);

			digest.update(salt, 0, salt.Length);
			digest.update(output, 0, output.Length);
			digest.doFinal(output, 0);

			return new BigInteger(1, output);
		}

		public static BigInteger generatePrivateValue(Digest digest, BigInteger N, BigInteger g, SecureRandom random)
		{
			int minBits = Math.Min(256, N.bitLength() / 2);
			BigInteger min = ONE.shiftLeft(minBits - 1);
			BigInteger max = N.subtract(ONE);

			return BigIntegers.createRandomInRange(min, max, random);
		}

		public static BigInteger validatePublicValue(BigInteger N, BigInteger val)
		{
			val = val.mod(N);

			// Check that val % N != 0
			if (val.Equals(ZERO))
			{
				throw new CryptoException("Invalid public value: 0");
			}

			return val;
		}

		/// <summary>
		/// Computes the client evidence message (M1) according to the standard routine:
		/// M1 = H( A | B | S ) </summary>
		/// <param name="digest"> The Digest used as the hashing function H </param>
		/// <param name="N"> Modulus used to get the pad length </param>
		/// <param name="A"> The public client value </param>
		/// <param name="B"> The public server value </param>
		/// <param name="S"> The secret calculated by both sides </param>
		/// <returns> M1 The calculated client evidence message </returns>
		public static BigInteger calculateM1(Digest digest, BigInteger N, BigInteger A, BigInteger B, BigInteger S)
		{
			BigInteger M1 = hashPaddedTriplet(digest,N,A,B,S);
			return M1;
		}

		/// <summary>
		/// Computes the server evidence message (M2) according to the standard routine:
		/// M2 = H( A | M1 | S ) </summary>
		/// <param name="digest"> The Digest used as the hashing function H </param>
		/// <param name="N"> Modulus used to get the pad length </param>
		/// <param name="A"> The public client value </param>
		/// <param name="M1"> The client evidence message </param>
		/// <param name="S"> The secret calculated by both sides </param>
		/// <returns> M2 The calculated server evidence message </returns>
		public static BigInteger calculateM2(Digest digest, BigInteger N, BigInteger A, BigInteger M1, BigInteger S)
		{
			BigInteger M2 = hashPaddedTriplet(digest,N,A,M1,S);
			return M2;
		}

		/// <summary>
		/// Computes the final Key according to the standard routine: Key = H(S) </summary>
		/// <param name="digest"> The Digest used as the hashing function H </param>
		/// <param name="N"> Modulus used to get the pad length </param>
		/// <param name="S"> The secret calculated by both sides </param>
		/// <returns> the final Key value. </returns>
		public static BigInteger calculateKey(Digest digest, BigInteger N, BigInteger S)
		{
			int padLength = (N.bitLength() + 7) / 8;
			byte[] _S = getPadded(S,padLength);
			digest.update(_S, 0, _S.Length);

			byte[] output = new byte[digest.getDigestSize()];
			digest.doFinal(output, 0);
			return new BigInteger(1, output);
		}

		private static BigInteger hashPaddedTriplet(Digest digest, BigInteger N, BigInteger n1, BigInteger n2, BigInteger n3)
		{
			int padLength = (N.bitLength() + 7) / 8;

			byte[] n1_bytes = getPadded(n1, padLength);
			byte[] n2_bytes = getPadded(n2, padLength);
			byte[] n3_bytes = getPadded(n3, padLength);

			digest.update(n1_bytes, 0, n1_bytes.Length);
			digest.update(n2_bytes, 0, n2_bytes.Length);
			digest.update(n3_bytes, 0, n3_bytes.Length);

			byte[] output = new byte[digest.getDigestSize()];
			digest.doFinal(output, 0);

			return new BigInteger(1, output);
		}

		private static BigInteger hashPaddedPair(Digest digest, BigInteger N, BigInteger n1, BigInteger n2)
		{
			int padLength = (N.bitLength() + 7) / 8;

			byte[] n1_bytes = getPadded(n1, padLength);
			byte[] n2_bytes = getPadded(n2, padLength);

			digest.update(n1_bytes, 0, n1_bytes.Length);
			digest.update(n2_bytes, 0, n2_bytes.Length);

			byte[] output = new byte[digest.getDigestSize()];
			digest.doFinal(output, 0);

			return new BigInteger(1, output);
		}

		private static byte[] getPadded(BigInteger n, int length)
		{
			byte[] bs = BigIntegers.asUnsignedByteArray(n);
			if (bs.Length < length)
			{
				byte[] tmp = new byte[length];
				JavaSystem.arraycopy(bs, 0, tmp, length - bs.Length, bs.Length);
				bs = tmp;
			}
			return bs;
		}
	}

}