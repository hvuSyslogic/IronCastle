using BouncyCastle.Core;
using BouncyCastle.Core.Port;
using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.engines
{

					
	/// <summary>
	/// this does your basic ElGamal algorithm.
	/// </summary>
	public class ElGamalEngine : AsymmetricBlockCipher
	{
		private ElGamalKeyParameters key;
		private SecureRandom random;
		private bool forEncryption;
		private int bitSize;

		private static readonly BigInteger ZERO = BigInteger.valueOf(0);
		private static readonly BigInteger ONE = BigInteger.valueOf(1);
		private static readonly BigInteger TWO = BigInteger.valueOf(2);

		/// <summary>
		/// initialise the ElGamal engine.
		/// </summary>
		/// <param name="forEncryption"> true if we are encrypting, false otherwise. </param>
		/// <param name="param"> the necessary ElGamal key parameters. </param>
		public virtual void init(bool forEncryption, CipherParameters param)
		{
			if (param is ParametersWithRandom)
			{
			    {	ParametersWithRandom p = (ParametersWithRandom)param;

				this.key = (ElGamalKeyParameters)p.getParameters();
				this.random = p.getRandom();
			    }
            }
			else
			{
				this.key = (ElGamalKeyParameters)param;
				this.random = CryptoServicesRegistrar.getSecureRandom();
			}

			this.forEncryption = forEncryption;

		    {BigInteger p = key.getParameters().getP();

			bitSize = p.bitLength();
		    }

            if (forEncryption)
			{
				if (!(key is ElGamalPublicKeyParameters))
				{
					throw new IllegalArgumentException("ElGamalPublicKeyParameters are required for encryption.");
				}
			}
			else
			{
				if (!(key is ElGamalPrivateKeyParameters))
				{
					throw new IllegalArgumentException("ElGamalPrivateKeyParameters are required for decryption.");
				}
			}
		}

		/// <summary>
		/// Return the maximum size for an input block to this engine.
		/// For ElGamal this is always one byte less than the size of P on
		/// encryption, and twice the length as the size of P on decryption.
		/// </summary>
		/// <returns> maximum size for an input block. </returns>
		public virtual int getInputBlockSize()
		{
			if (forEncryption)
			{
				return (bitSize - 1) / 8;
			}

			return 2 * ((bitSize + 7) / 8);
		}

		/// <summary>
		/// Return the maximum size for an output block to this engine.
		/// For ElGamal this is always one byte less than the size of P on
		/// decryption, and twice the length as the size of P on encryption.
		/// </summary>
		/// <returns> maximum size for an output block. </returns>
		public virtual int getOutputBlockSize()
		{
			if (forEncryption)
			{
				return 2 * ((bitSize + 7) / 8);
			}

			return (bitSize - 1) / 8;
		}

		/// <summary>
		/// Process a single block using the basic ElGamal algorithm.
		/// </summary>
		/// <param name="in"> the input array. </param>
		/// <param name="inOff"> the offset into the input buffer where the data starts. </param>
		/// <param name="inLen"> the length of the data to be processed. </param>
		/// <returns> the result of the ElGamal process. </returns>
		/// <exception cref="DataLengthException"> the input block is too large. </exception>
		public virtual byte[] processBlock(byte[] @in, int inOff, int inLen)
		{
			if (key == null)
			{
				throw new IllegalStateException("ElGamal engine not initialised");
			}

			int maxLength = forEncryption ? (bitSize - 1 + 7) / 8 : getInputBlockSize();

			if (inLen > maxLength)
			{
				throw new DataLengthException("input too large for ElGamal cipher.\n");
			}

			BigInteger p = key.getParameters().getP();

			if (key is ElGamalPrivateKeyParameters) // decryption
			{
				byte[] in1 = new byte[inLen / 2];
				byte[] in2 = new byte[inLen / 2];

				JavaSystem.arraycopy(@in, inOff, in1, 0, in1.Length);
				JavaSystem.arraycopy(@in, inOff + in1.Length, in2, 0, in2.Length);

				BigInteger gamma = new BigInteger(1, in1);
				BigInteger phi = new BigInteger(1, in2);

				ElGamalPrivateKeyParameters priv = (ElGamalPrivateKeyParameters)key;
				// a shortcut, which generally relies on p being prime amongst other things.
				// if a problem with this shows up, check the p and g values!
				BigInteger m = gamma.modPow(p.subtract(ONE).subtract(priv.getX()), p).multiply(phi).mod(p);

				return BigIntegers.asUnsignedByteArray(m);
			}
			else // encryption
			{
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

				BigInteger input = new BigInteger(1, block);

				if (input.compareTo(p) >= 0)
				{
					throw new DataLengthException("input too large for ElGamal cipher.\n");
				}

				ElGamalPublicKeyParameters pub = (ElGamalPublicKeyParameters)key;

				int pBitLength = p.bitLength();
				BigInteger k = BigIntegers.createRandomBigInteger(pBitLength, random);

				while (k.Equals(ZERO) || (k.compareTo(p.subtract(TWO)) > 0))
				{
					k = BigIntegers.createRandomBigInteger(pBitLength, random);
				}

				BigInteger g = key.getParameters().getG();
				BigInteger gamma = g.modPow(k, p);
				BigInteger phi = input.multiply(pub.getY().modPow(k, p)).mod(p);

				byte[] out1 = gamma.toByteArray();
				byte[] out2 = phi.toByteArray();
				byte[] output = new byte[this.getOutputBlockSize()];

				if (out1.Length > output.Length / 2)
				{
					JavaSystem.arraycopy(out1, 1, output, output.Length / 2 - (out1.Length - 1), out1.Length - 1);
				}
				else
				{
					JavaSystem.arraycopy(out1, 0, output, output.Length / 2 - out1.Length, out1.Length);
				}

				if (out2.Length > output.Length / 2)
				{
					JavaSystem.arraycopy(out2, 1, output, output.Length - (out2.Length - 1), out2.Length - 1);
				}
				else
				{
					JavaSystem.arraycopy(out2, 0, output, output.Length - out2.Length, out2.Length);
				}

				return output;
			}
		}
	}

}