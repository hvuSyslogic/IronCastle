using BouncyCastle.Core;
using BouncyCastle.Core.Port;
using org.bouncycastle.Port;

namespace org.bouncycastle.crypto.encodings
{

	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;
	using DigestFactory = org.bouncycastle.crypto.util.DigestFactory;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// Optimal Asymmetric Encryption Padding (OAEP) - see PKCS 1 V 2.
	/// </summary>
	public class OAEPEncoding : AsymmetricBlockCipher
	{
		private byte[] defHash;
		private Digest mgf1Hash;

		private AsymmetricBlockCipher engine;
		private SecureRandom random;
		private bool forEncryption;

		public OAEPEncoding(AsymmetricBlockCipher cipher) : this(cipher, DigestFactory.createSHA1(), null)
		{
		}

		public OAEPEncoding(AsymmetricBlockCipher cipher, Digest hash) : this(cipher, hash, null)
		{
		}

		public OAEPEncoding(AsymmetricBlockCipher cipher, Digest hash, byte[] encodingParams) : this(cipher, hash, hash, encodingParams)
		{
		}

		public OAEPEncoding(AsymmetricBlockCipher cipher, Digest hash, Digest mgf1Hash, byte[] encodingParams)
		{
			this.engine = cipher;
			this.mgf1Hash = mgf1Hash;
			this.defHash = new byte[hash.getDigestSize()];

			hash.reset();

			if (encodingParams != null)
			{
				hash.update(encodingParams, 0, encodingParams.Length);
			}

			hash.doFinal(defHash, 0);
		}

		public virtual AsymmetricBlockCipher getUnderlyingCipher()
		{
			return engine;
		}

		public virtual void init(bool forEncryption, CipherParameters param)
		{
			if (param is ParametersWithRandom)
			{
				ParametersWithRandom rParam = (ParametersWithRandom)param;

				this.random = rParam.getRandom();
			}
			else
			{
				this.random = CryptoServicesRegistrar.getSecureRandom();
			}

			engine.init(forEncryption, param);

			this.forEncryption = forEncryption;
		}

		public virtual int getInputBlockSize()
		{
			int baseBlockSize = engine.getInputBlockSize();

			if (forEncryption)
			{
				return baseBlockSize - 1 - 2 * defHash.Length;
			}
			else
			{
				return baseBlockSize;
			}
		}

		public virtual int getOutputBlockSize()
		{
			int baseBlockSize = engine.getOutputBlockSize();

			if (forEncryption)
			{
				return baseBlockSize;
			}
			else
			{
				return baseBlockSize - 1 - 2 * defHash.Length;
			}
		}

		public virtual byte[] processBlock(byte[] @in, int inOff, int inLen)
		{
			if (forEncryption)
			{
				return encodeBlock(@in, inOff, inLen);
			}
			else
			{
				return decodeBlock(@in, inOff, inLen);
			}
		}

		public virtual byte[] encodeBlock(byte[] @in, int inOff, int inLen)
		{
			if (inLen > getInputBlockSize())
			{
				throw new DataLengthException("input data too long");
			}

			byte[] block = new byte[getInputBlockSize() + 1 + 2 * defHash.Length];

			//
			// copy in the message
			//
			JavaSystem.arraycopy(@in, inOff, block, block.Length - inLen, inLen);

			//
			// add sentinel
			//
			block[block.Length - inLen - 1] = 0x01;

			//
			// as the block is already zeroed - there's no need to add PS (the >= 0 pad of 0)
			//

			//
			// add the hash of the encoding params.
			//
			JavaSystem.arraycopy(defHash, 0, block, defHash.Length, defHash.Length);

			//
			// generate the seed.
			//
			byte[] seed = new byte[defHash.Length];

			random.nextBytes(seed);

			//
			// mask the message block.
			//
			byte[] mask = maskGeneratorFunction1(seed, 0, seed.Length, block.Length - defHash.Length);

			for (int i = defHash.Length; i != block.Length; i++)
			{
				block[i] ^= mask[i - defHash.Length];
			}

			//
			// add in the seed
			//
			JavaSystem.arraycopy(seed, 0, block, 0, defHash.Length);

			//
			// mask the seed.
			//
			mask = maskGeneratorFunction1(block, defHash.Length, block.Length - defHash.Length, defHash.Length);

			for (int i = 0; i != defHash.Length; i++)
			{
				block[i] ^= mask[i];
			}

			return engine.processBlock(block, 0, block.Length);
		}

		/// <exception cref="InvalidCipherTextException"> if the decrypted block turns out to
		/// be badly formatted. </exception>
		public virtual byte[] decodeBlock(byte[] @in, int inOff, int inLen)
		{
			byte[] data = engine.processBlock(@in, inOff, inLen);
			byte[] block = new byte[engine.getOutputBlockSize()];

			//
			// as we may have zeros in our leading bytes for the block we produced
			// on encryption, we need to make sure our decrypted block comes back
			// the same size.
			//
			bool wrongData = (block.Length < (2 * defHash.Length) + 1);

			if (data.Length <= block.Length)
			{
				JavaSystem.arraycopy(data, 0, block, block.Length - data.Length, data.Length);
			}
			else
			{
				JavaSystem.arraycopy(data, 0, block, 0, block.Length);
				wrongData = true;
			}

			//
			// unmask the seed.
			//
			byte[] mask = maskGeneratorFunction1(block, defHash.Length, block.Length - defHash.Length, defHash.Length);

			for (int i = 0; i != defHash.Length; i++)
			{
				block[i] ^= mask[i];
			}

			//
			// unmask the message block.
			//
			mask = maskGeneratorFunction1(block, 0, defHash.Length, block.Length - defHash.Length);

			for (int i = defHash.Length; i != block.Length; i++)
			{
				block[i] ^= mask[i - defHash.Length];
			}

			//
			// check the hash of the encoding params.
			// long check to try to avoid this been a source of a timing attack.
			//
			bool defHashWrong = false;

			for (int i = 0; i != defHash.Length; i++)
			{
				if (defHash[i] != block[defHash.Length + i])
				{
					defHashWrong = true;
				}
			}

			//
			// find the data block
			//
			int start = block.Length;

			for (int index = 2 * defHash.Length; index != block.Length; index++)
			{
				if (block[index] != 0 & start == block.Length)
				{
					start = index;
				}
			}

			bool dataStartWrong = (start > (block.Length - 1) | block[start] != 1);

			start++;

			if (defHashWrong | wrongData | dataStartWrong)
			{
				Arrays.fill(block, (byte)0);
				throw new InvalidCipherTextException("data wrong");
			}

			//
			// extract the data block
			//
			byte[] output = new byte[block.Length - start];

			JavaSystem.arraycopy(block, start, output, 0, output.Length);

			return output;
		}

		/// <summary>
		/// int to octet string.
		/// </summary>
		private void ItoOSP(int i, byte[] sp)
		{
			sp[0] = (byte)((int)((uint)i >> 24));
			sp[1] = (byte)((int)((uint)i >> 16));
			sp[2] = (byte)((int)((uint)i >> 8));
			sp[3] = (byte)((int)((uint)i >> 0));
		}

		/// <summary>
		/// mask generator function, as described in PKCS1v2.
		/// </summary>
		private byte[] maskGeneratorFunction1(byte[] Z, int zOff, int zLen, int length)
		{
			byte[] mask = new byte[length];
			byte[] hashBuf = new byte[mgf1Hash.getDigestSize()];
			byte[] C = new byte[4];
			int counter = 0;

			mgf1Hash.reset();

			while (counter < (length / hashBuf.Length))
			{
				ItoOSP(counter, C);

				mgf1Hash.update(Z, zOff, zLen);
				mgf1Hash.update(C, 0, C.Length);
				mgf1Hash.doFinal(hashBuf, 0);

				JavaSystem.arraycopy(hashBuf, 0, mask, counter * hashBuf.Length, hashBuf.Length);

				counter++;
			}

			if ((counter * hashBuf.Length) < length)
			{
				ItoOSP(counter, C);

				mgf1Hash.update(Z, zOff, zLen);
				mgf1Hash.update(C, 0, C.Length);
				mgf1Hash.doFinal(hashBuf, 0);

				JavaSystem.arraycopy(hashBuf, 0, mask, counter * hashBuf.Length, mask.Length - (counter * hashBuf.Length));
			}

			return mask;
		}
	}

}