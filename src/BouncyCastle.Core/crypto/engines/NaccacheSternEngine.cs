using BouncyCastle.Core.Port;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.crypto.engines
{
	using Arrays = org.bouncycastle.util.Arrays;

	using NaccacheSternKeyParameters = org.bouncycastle.crypto.@params.NaccacheSternKeyParameters;
	using NaccacheSternPrivateKeyParameters = org.bouncycastle.crypto.@params.NaccacheSternPrivateKeyParameters;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;

	/// <summary>
	/// NaccacheStern Engine. For details on this cipher, please see
	/// http://www.gemplus.com/smart/rd/publications/pdf/NS98pkcs.pdf
	/// </summary>
	public class NaccacheSternEngine : AsymmetricBlockCipher
	{
		private bool forEncryption;

		private NaccacheSternKeyParameters key;

		private Vector[] lookup = null;

		private bool debug = false;

		private static BigInteger ZERO = BigInteger.valueOf(0);
		private static BigInteger ONE = BigInteger.valueOf(1);

		/// <summary>
		/// Initializes this algorithm. Must be called before all other Functions.
		/// </summary>
		/// <seealso cref= org.bouncycastle.crypto.AsymmetricBlockCipher#init(boolean,
		///      org.bouncycastle.crypto.CipherParameters) </seealso>
		public virtual void init(bool forEncryption, CipherParameters param)
		{
			this.forEncryption = forEncryption;

			if (param is ParametersWithRandom)
			{
				param = ((ParametersWithRandom) param).getParameters();
			}

			key = (NaccacheSternKeyParameters)param;

			// construct lookup table for faster decryption if necessary
			if (!this.forEncryption)
			{
				if (debug)
				{
					JavaSystem.@out.println("Constructing lookup Array");
				}
				NaccacheSternPrivateKeyParameters priv = (NaccacheSternPrivateKeyParameters)key;
				Vector primes = priv.getSmallPrimes();
				lookup = new Vector[primes.size()];
				for (int i = 0; i < primes.size(); i++)
				{
					BigInteger actualPrime = (BigInteger)primes.elementAt(i);
					int actualPrimeValue = actualPrime.intValue();

					lookup[i] = new Vector();
					lookup[i].addElement(ONE);

					if (debug)
					{
						JavaSystem.@out.println("Constructing lookup ArrayList for " + actualPrimeValue);
					}

					BigInteger accJ = ZERO;

					for (int j = 1; j < actualPrimeValue; j++)
					{
						accJ = accJ.add(priv.getPhi_n());
						BigInteger comp = accJ.divide(actualPrime);
						lookup[i].addElement(priv.getG().modPow(comp, priv.getModulus()));
					}
				}
			}
		}

		public virtual void setDebug(bool debug)
		{
			this.debug = debug;
		}

		/// <summary>
		/// Returns the input block size of this algorithm.
		/// </summary>
		/// <seealso cref= org.bouncycastle.crypto.AsymmetricBlockCipher#getInputBlockSize() </seealso>
		public virtual int getInputBlockSize()
		{
			if (forEncryption)
			{
				// We can only encrypt values up to lowerSigmaBound
				return (key.getLowerSigmaBound() + 7) / 8 - 1;
			}
			else
			{
				// We pad to modulus-size bytes for easier decryption.
				return key.getModulus().toByteArray().Length;
			}
		}

		/// <summary>
		/// Returns the output block size of this algorithm.
		/// </summary>
		/// <seealso cref= org.bouncycastle.crypto.AsymmetricBlockCipher#getOutputBlockSize() </seealso>
		public virtual int getOutputBlockSize()
		{
			if (forEncryption)
			{
				// encrypted Data is always padded up to modulus size
				return key.getModulus().toByteArray().Length;
			}
			else
			{
				// decrypted Data has upper limit lowerSigmaBound
				return (key.getLowerSigmaBound() + 7) / 8 - 1;
			}
		}

		/// <summary>
		/// Process a single Block using the Naccache-Stern algorithm.
		/// </summary>
		/// <seealso cref= org.bouncycastle.crypto.AsymmetricBlockCipher#processBlock(byte[],
		///      int, int) </seealso>
		public virtual byte[] processBlock(byte[] @in, int inOff, int len)
		{
			if (key == null)
			{
				throw new IllegalStateException("NaccacheStern engine not initialised");
			}
			if (len > (getInputBlockSize() + 1))
			{
				throw new DataLengthException("input too large for Naccache-Stern cipher.\n");
			}

			if (!forEncryption)
			{
				// At decryption make sure that we receive padded data blocks
				if (len < getInputBlockSize())
				{
					throw new InvalidCipherTextException("BlockLength does not match modulus for Naccache-Stern cipher.\n");
				}
			}

			byte[] block;

			if (inOff != 0 || len != @in.Length)
			{
				block = new byte[len];
				JavaSystem.arraycopy(@in, inOff, block, 0, len);
			}
			else
			{
				block = @in;
			}

			// transform input into BigInteger
			BigInteger input = new BigInteger(1, block);
			if (debug)
			{
				JavaSystem.@out.println("input as BigInteger: " + input);
			}
			byte[] output;
			if (forEncryption)
			{
				output = encrypt(input);
			}
			else
			{
				Vector plain = new Vector();
				NaccacheSternPrivateKeyParameters priv = (NaccacheSternPrivateKeyParameters)key;
				Vector primes = priv.getSmallPrimes();
				// Get Chinese Remainders of CipherText
				for (int i = 0; i < primes.size(); i++)
				{
					BigInteger exp = input.modPow(priv.getPhi_n().divide((BigInteger)primes.elementAt(i)), priv.getModulus());
					Vector al = lookup[i];
					if (lookup[i].size() != ((BigInteger)primes.elementAt(i)).intValue())
					{
						if (debug)
						{
							JavaSystem.@out.println("Prime is " + primes.elementAt(i) + ", lookup table has size " + al.size());
						}
						throw new InvalidCipherTextException("Error in lookup Array for " + ((BigInteger)primes.elementAt(i)).intValue() + ": Size mismatch. Expected ArrayList with length " + ((BigInteger)primes.elementAt(i)).intValue() + " but found ArrayList of length " + lookup[i].size());
					}
					int lookedup = al.indexOf(exp);

					if (lookedup == -1)
					{
						if (debug)
						{
							JavaSystem.@out.println("Actual prime is " + primes.elementAt(i));
							JavaSystem.@out.println("Decrypted value is " + exp);

							JavaSystem.@out.println("LookupList for " + primes.elementAt(i) + " with size " + lookup[i].size() + " is: ");
							for (int j = 0; j < lookup[i].size(); j++)
							{
								JavaSystem.@out.println(lookup[i].elementAt(j));
							}
						}
						throw new InvalidCipherTextException("Lookup failed");
					}
					plain.addElement(BigInteger.valueOf(lookedup));
				}
				BigInteger test = chineseRemainder(plain, primes);

				// Should not be used as an oracle, so reencrypt output to see
				// if it corresponds to input

				// this breaks probabilisic encryption, so disable it. Anyway, we do
				// use the first n primes for key generation, so it is pretty easy
				// to guess them. But as stated in the paper, this is not a security
				// breach. So we can just work with the correct sigma.

				// if (debug) {
				//      JavaSystem.@out.println("Decryption is " + test);
				// }
				// if ((key.getG().modPow(test, key.getModulus())).equals(input)) {
				//      output = test.toByteArray();
				// } else {
				//      if(debug){
				//          JavaSystem.@out.println("Engine seems to be used as an oracle,
				//          returning null");
				//      }
				//      output = null;
				// }

				output = test.toByteArray();

			}

			return output;
		}

		/// <summary>
		/// Encrypts a BigInteger aka Plaintext with the public key.
		/// </summary>
		/// <param name="plain">
		///            The BigInteger to encrypt </param>
		/// <returns> The byte[] representation of the encrypted BigInteger (i.e.
		///         crypted.toByteArray()) </returns>
		public virtual byte[] encrypt(BigInteger plain)
		{
			// Always return modulus size values 0-padded at the beginning
			// 0-padding at the beginning is correctly parsed by BigInteger :)
			byte[] output = key.getModulus().toByteArray();
			Arrays.fill(output, (byte)0);
			byte[] tmp = key.getG().modPow(plain, key.getModulus()).toByteArray();
			JavaSystem.arraycopy(tmp, 0, output, output.Length - tmp.Length, tmp.Length);
			if (debug)
			{
				JavaSystem.@out.println("Encrypted value is:  " + new BigInteger(output));
			}
			return output;
		}

		/// <summary>
		/// Adds the contents of two encrypted blocks mod sigma
		/// </summary>
		/// <param name="block1">
		///            the first encrypted block </param>
		/// <param name="block2">
		///            the second encrypted block </param>
		/// <returns> encrypt((block1 + block2) mod sigma) </returns>
		/// <exception cref="InvalidCipherTextException"> </exception>
		public virtual byte[] addCryptedBlocks(byte[] block1, byte[] block2)
		{
			// check for correct blocksize
			if (forEncryption)
			{
				if ((block1.Length > getOutputBlockSize()) || (block2.Length > getOutputBlockSize()))
				{
					throw new InvalidCipherTextException("BlockLength too large for simple addition.\n");
				}
			}
			else
			{
				if ((block1.Length > getInputBlockSize()) || (block2.Length > getInputBlockSize()))
				{
					throw new InvalidCipherTextException("BlockLength too large for simple addition.\n");
				}
			}

			// calculate resulting block
			BigInteger m1Crypt = new BigInteger(1, block1);
			BigInteger m2Crypt = new BigInteger(1, block2);
			BigInteger m1m2Crypt = m1Crypt.multiply(m2Crypt);
			m1m2Crypt = m1m2Crypt.mod(key.getModulus());
			if (debug)
			{
				JavaSystem.@out.println("c(m1) as BigInteger:....... " + m1Crypt);
				JavaSystem.@out.println("c(m2) as BigInteger:....... " + m2Crypt);
				JavaSystem.@out.println("c(m1)*c(m2)%n = c(m1+m2)%n: " + m1m2Crypt);
			}

			byte[] output = key.getModulus().toByteArray();
			Arrays.fill(output, (byte)0);
			JavaSystem.arraycopy(m1m2Crypt.toByteArray(), 0, output, output.Length - m1m2Crypt.toByteArray().Length, m1m2Crypt.toByteArray().Length);

			return output;
		}

		/// <summary>
		/// Convenience Method for data exchange with the cipher.
		/// 
		/// Determines blocksize and splits data to blocksize.
		/// </summary>
		/// <param name="data"> the data to be processed </param>
		/// <returns> the data after it went through the NaccacheSternEngine. </returns>
		/// <exception cref="InvalidCipherTextException">  </exception>
		public virtual byte[] processData(byte[] data)
		{
			if (debug)
			{
				JavaSystem.@out.println();
			}
			if (data.Length > getInputBlockSize())
			{
				int inBlocksize = getInputBlockSize();
				int outBlocksize = getOutputBlockSize();
				if (debug)
				{
					JavaSystem.@out.println("Input blocksize is:  " + inBlocksize + " bytes");
					JavaSystem.@out.println("Output blocksize is: " + outBlocksize + " bytes");
					JavaSystem.@out.println("Data has length:.... " + data.Length + " bytes");
				}
				int datapos = 0;
				int retpos = 0;
				byte[] retval = new byte[(data.Length / inBlocksize + 1) * outBlocksize];
				while (datapos < data.Length)
				{
					byte[] tmp;
					if (datapos + inBlocksize < data.Length)
					{
						tmp = processBlock(data, datapos, inBlocksize);
						datapos += inBlocksize;
					}
					else
					{
						tmp = processBlock(data, datapos, data.Length - datapos);
						datapos += data.Length - datapos;
					}
					if (debug)
					{
						JavaSystem.@out.println("new datapos is " + datapos);
					}
					if (tmp != null)
					{
						JavaSystem.arraycopy(tmp, 0, retval, retpos, tmp.Length);

						retpos += tmp.Length;
					}
					else
					{
						if (debug)
						{
							JavaSystem.@out.println("cipher returned null");
						}
						throw new InvalidCipherTextException("cipher returned null");
					}
				}
				byte[] ret = new byte[retpos];
				JavaSystem.arraycopy(retval, 0, ret, 0, retpos);
				if (debug)
				{
					JavaSystem.@out.println("returning " + ret.Length + " bytes");
				}
				return ret;
			}
			else
			{
				if (debug)
				{
					JavaSystem.@out.println("data size is less then input block size, processing directly");
				}
				return processBlock(data, 0, data.Length);
			}
		}

		/// <summary>
		/// Computes the integer x that is expressed through the given primes and the
		/// congruences with the chinese remainder theorem (CRT).
		/// </summary>
		/// <param name="congruences">
		///            the congruences c_i </param>
		/// <param name="primes">
		///            the primes p_i </param>
		/// <returns> an integer x for that x % p_i == c_i </returns>
		private static BigInteger chineseRemainder(Vector congruences, Vector primes)
		{
			BigInteger retval = ZERO;
			BigInteger all = ONE;
			for (int i = 0; i < primes.size(); i++)
			{
				all = all.multiply((BigInteger)primes.elementAt(i));
			}
			for (int i = 0; i < primes.size(); i++)
			{
				BigInteger a = (BigInteger)primes.elementAt(i);
				BigInteger b = all.divide(a);
				BigInteger b_ = b.modInverse(a);
				BigInteger tmp = b.multiply(b_);
				tmp = tmp.multiply((BigInteger)congruences.elementAt(i));
				retval = retval.add(tmp);
			}

			return retval.mod(all);
		}
	}

}