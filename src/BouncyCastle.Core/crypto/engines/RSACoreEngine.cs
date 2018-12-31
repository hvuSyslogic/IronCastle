using BouncyCastle.Core.Port;
using org.bouncycastle.Port;

namespace org.bouncycastle.crypto.engines
{

	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;
	using RSAKeyParameters = org.bouncycastle.crypto.@params.RSAKeyParameters;
	using RSAPrivateCrtKeyParameters = org.bouncycastle.crypto.@params.RSAPrivateCrtKeyParameters;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// this does your basic RSA algorithm.
	/// </summary>
	public class RSACoreEngine
	{
		private RSAKeyParameters key;
		private bool forEncryption;

		/// <summary>
		/// initialise the RSA engine.
		/// </summary>
		/// <param name="forEncryption"> true if we are encrypting, false otherwise. </param>
		/// <param name="param"> the necessary RSA key parameters. </param>
		public virtual void init(bool forEncryption, CipherParameters param)
		{
			if (param is ParametersWithRandom)
			{
				ParametersWithRandom rParam = (ParametersWithRandom)param;

				key = (RSAKeyParameters)rParam.getParameters();
			}
			else
			{
				key = (RSAKeyParameters)param;
			}

			this.forEncryption = forEncryption;
		}

		/// <summary>
		/// Return the maximum size for an input block to this engine.
		/// For RSA this is always one byte less than the key size on
		/// encryption, and the same length as the key size on decryption.
		/// </summary>
		/// <returns> maximum size for an input block. </returns>
		public virtual int getInputBlockSize()
		{
			int bitSize = key.getModulus().bitLength();

			if (forEncryption)
			{
				return (bitSize + 7) / 8 - 1;
			}
			else
			{
				return (bitSize + 7) / 8;
			}
		}

		/// <summary>
		/// Return the maximum size for an output block to this engine.
		/// For RSA this is always one byte less than the key size on
		/// decryption, and the same length as the key size on encryption.
		/// </summary>
		/// <returns> maximum size for an output block. </returns>
		public virtual int getOutputBlockSize()
		{
			int bitSize = key.getModulus().bitLength();

			if (forEncryption)
			{
				return (bitSize + 7) / 8;
			}
			else
			{
				return (bitSize + 7) / 8 - 1;
			}
		}

		public virtual BigInteger convertInput(byte[] @in, int inOff, int inLen)
		{
			if (inLen > (getInputBlockSize() + 1))
			{
				throw new DataLengthException("input too large for RSA cipher.");
			}
			else if (inLen == (getInputBlockSize() + 1) && !forEncryption)
			{
				throw new DataLengthException("input too large for RSA cipher.");
			}

			byte[] block;

			if (inOff != 0 || inLen != @in.Length)
			{
				block = new byte[inLen];

				JavaSystem.arraycopy(@in, inOff, block, 0, inLen);
			}
			else
			{
				block = @in;
			}

			BigInteger res = new BigInteger(1, block);
			if (res.compareTo(key.getModulus()) >= 0)
			{
				throw new DataLengthException("input too large for RSA cipher.");
			}

			return res;
		}

		public virtual byte[] convertOutput(BigInteger result)
		{
			byte[] output = result.toByteArray();

			if (forEncryption)
			{
				if (output[0] == 0 && output.Length > getOutputBlockSize()) // have ended up with an extra zero byte, copy down.
				{
					byte[] tmp = new byte[output.Length - 1];

					JavaSystem.arraycopy(output, 1, tmp, 0, tmp.Length);

					return tmp;
				}

				if (output.Length < getOutputBlockSize()) // have ended up with less bytes than normal, lengthen
				{
					byte[] tmp = new byte[getOutputBlockSize()];

					JavaSystem.arraycopy(output, 0, tmp, tmp.Length - output.Length, output.Length);

					return tmp;
				}

				return output;
			}
			else
			{
				byte[] rv;
				if (output[0] == 0) // have ended up with an extra zero byte, copy down.
				{
					rv = new byte[output.Length - 1];

					JavaSystem.arraycopy(output, 1, rv, 0, rv.Length);
				}
				else // maintain decryption time
				{
					rv = new byte[output.Length];

					JavaSystem.arraycopy(output, 0, rv, 0, rv.Length);
				}

				Arrays.fill(output, 0);

				return rv;
			}
		}

		public virtual BigInteger processBlock(BigInteger input)
		{
			if (key is RSAPrivateCrtKeyParameters)
			{
				//
				// we have the extra factors, use the Chinese Remainder Theorem - the author
				// wishes to express his thanks to Dirk Bonekaemper at rtsffm.com for
				// advice regarding the expression of this.
				//
				RSAPrivateCrtKeyParameters crtKey = (RSAPrivateCrtKeyParameters)key;

				BigInteger p = crtKey.getP();
				BigInteger q = crtKey.getQ();
				BigInteger dP = crtKey.getDP();
				BigInteger dQ = crtKey.getDQ();
				BigInteger qInv = crtKey.getQInv();

				BigInteger mP, mQ, h, m;

				// mP = ((input mod p) ^ dP)) mod p
				mP = (input.remainder(p)).modPow(dP, p);

				// mQ = ((input mod q) ^ dQ)) mod q
				mQ = (input.remainder(q)).modPow(dQ, q);

				// h = qInv * (mP - mQ) mod p
				h = mP.subtract(mQ);
				h = h.multiply(qInv);
				h = h.mod(p); // mod (in Java) returns the positive residual

				// m = h * q + mQ
				m = h.multiply(q);
				m = m.add(mQ);

				return m;
			}
			else
			{
				return input.modPow(key.getExponent(), key.getModulus());
			}
		}
	}

}