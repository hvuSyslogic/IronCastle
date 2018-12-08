using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.modes
{
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// implements Cipher-Block-Chaining (CBC) mode on top of a simple cipher.
	/// </summary>
	public class CBCBlockCipher : BlockCipher
	{
		private byte[] IV;
		private byte[] cbcV;
		private byte[] cbcNextV;

		private int blockSize;
		private BlockCipher cipher = null;
		private bool encrypting;

		/// <summary>
		/// Basic constructor.
		/// </summary>
		/// <param name="cipher"> the block cipher to be used as the basis of chaining. </param>
		public CBCBlockCipher(BlockCipher cipher)
		{
			this.cipher = cipher;
			this.blockSize = cipher.getBlockSize();

			this.IV = new byte[blockSize];
			this.cbcV = new byte[blockSize];
			this.cbcNextV = new byte[blockSize];
		}

		/// <summary>
		/// return the underlying block cipher that we are wrapping.
		/// </summary>
		/// <returns> the underlying block cipher that we are wrapping. </returns>
		public virtual BlockCipher getUnderlyingCipher()
		{
			return cipher;
		}

		/// <summary>
		/// Initialise the cipher and, possibly, the initialisation vector (IV).
		/// If an IV isn't passed as part of the parameter, the IV will be all zeros.
		/// </summary>
		/// <param name="encrypting"> if true the cipher is initialised for
		///  encryption, if false for decryption. </param>
		/// <param name="params"> the key and other data required by the cipher. </param>
		/// <exception cref="IllegalArgumentException"> if the params argument is
		/// inappropriate. </exception>
		public virtual void init(bool encrypting, CipherParameters @params)
		{
			bool oldEncrypting = this.encrypting;

			this.encrypting = encrypting;

			if (@params is ParametersWithIV)
			{
				ParametersWithIV ivParam = (ParametersWithIV)@params;
				byte[] iv = ivParam.getIV();

				if (iv.Length != blockSize)
				{
					throw new IllegalArgumentException("initialisation vector must be the same length as block size");
				}

				JavaSystem.arraycopy(iv, 0, IV, 0, iv.Length);

				reset();

				// if null it's an IV changed only.
				if (ivParam.getParameters() != null)
				{
					cipher.init(encrypting, ivParam.getParameters());
				}
				else if (oldEncrypting != encrypting)
				{
					throw new IllegalArgumentException("cannot change encrypting state without providing key.");
				}
			}
			else
			{
				reset();

				// if it's null, key is to be reused.
				if (@params != null)
				{
					cipher.init(encrypting, @params);
				}
				else if (oldEncrypting != encrypting)
				{
					throw new IllegalArgumentException("cannot change encrypting state without providing key.");
				}
			}
		}

		/// <summary>
		/// return the algorithm name and mode.
		/// </summary>
		/// <returns> the name of the underlying algorithm followed by "/CBC". </returns>
		public virtual string getAlgorithmName()
		{
			return cipher.getAlgorithmName() + "/CBC";
		}

		/// <summary>
		/// return the block size of the underlying cipher.
		/// </summary>
		/// <returns> the block size of the underlying cipher. </returns>
		public virtual int getBlockSize()
		{
			return cipher.getBlockSize();
		}

		/// <summary>
		/// Process one block of input from the array in and write it to
		/// the out array.
		/// </summary>
		/// <param name="in"> the array containing the input data. </param>
		/// <param name="inOff"> offset into the in array the data starts at. </param>
		/// <param name="out"> the array the output data will be copied into. </param>
		/// <param name="outOff"> the offset into the out array the output will start at. </param>
		/// <exception cref="DataLengthException"> if there isn't enough data in in, or
		/// space in out. </exception>
		/// <exception cref="IllegalStateException"> if the cipher isn't initialised. </exception>
		/// <returns> the number of bytes processed and produced. </returns>
		public virtual int processBlock(byte[] @in, int inOff, byte[] @out, int outOff)
		{
			return (encrypting) ? encryptBlock(@in, inOff, @out, outOff) : decryptBlock(@in, inOff, @out, outOff);
		}

		/// <summary>
		/// reset the chaining vector back to the IV and reset the underlying
		/// cipher.
		/// </summary>
		public virtual void reset()
		{
			JavaSystem.arraycopy(IV, 0, cbcV, 0, IV.Length);
			Arrays.fill(cbcNextV, (byte)0);

			cipher.reset();
		}

		/// <summary>
		/// Do the appropriate chaining step for CBC mode encryption.
		/// </summary>
		/// <param name="in"> the array containing the data to be encrypted. </param>
		/// <param name="inOff"> offset into the in array the data starts at. </param>
		/// <param name="out"> the array the encrypted data will be copied into. </param>
		/// <param name="outOff"> the offset into the out array the output will start at. </param>
		/// <exception cref="DataLengthException"> if there isn't enough data in in, or
		/// space in out. </exception>
		/// <exception cref="IllegalStateException"> if the cipher isn't initialised. </exception>
		/// <returns> the number of bytes processed and produced. </returns>
		private int encryptBlock(byte[] @in, int inOff, byte[] @out, int outOff)
		{
			if ((inOff + blockSize) > @in.Length)
			{
				throw new DataLengthException("input buffer too short");
			}

			/*
			 * XOR the cbcV and the input,
			 * then encrypt the cbcV
			 */
			for (int i = 0; i < blockSize; i++)
			{
				cbcV[i] ^= @in[inOff + i];
			}

			int length = cipher.processBlock(cbcV, 0, @out, outOff);

			/*
			 * copy ciphertext to cbcV
			 */
			JavaSystem.arraycopy(@out, outOff, cbcV, 0, cbcV.Length);

			return length;
		}

		/// <summary>
		/// Do the appropriate chaining step for CBC mode decryption.
		/// </summary>
		/// <param name="in"> the array containing the data to be decrypted. </param>
		/// <param name="inOff"> offset into the in array the data starts at. </param>
		/// <param name="out"> the array the decrypted data will be copied into. </param>
		/// <param name="outOff"> the offset into the out array the output will start at. </param>
		/// <exception cref="DataLengthException"> if there isn't enough data in in, or
		/// space in out. </exception>
		/// <exception cref="IllegalStateException"> if the cipher isn't initialised. </exception>
		/// <returns> the number of bytes processed and produced. </returns>
		private int decryptBlock(byte[] @in, int inOff, byte[] @out, int outOff)
		{
			if ((inOff + blockSize) > @in.Length)
			{
				throw new DataLengthException("input buffer too short");
			}

			JavaSystem.arraycopy(@in, inOff, cbcNextV, 0, blockSize);

			int length = cipher.processBlock(@in, inOff, @out, outOff);

			/*
			 * XOR the cbcV and the output
			 */
			for (int i = 0; i < blockSize; i++)
			{
				@out[outOff + i] ^= cbcV[i];
			}

			/*
			 * swap the back up buffer into next position
			 */
			byte[] tmp;

			tmp = cbcV;
			cbcV = cbcNextV;
			cbcNextV = tmp;

			return length;
		}
	}

}