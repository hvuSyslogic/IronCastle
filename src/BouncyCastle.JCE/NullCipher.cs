namespace javax.crypto
{

	/// <summary>
	/// The NullCipher class is a class that provides an
	/// "identity cipher" -- one that does not tranform the plaintext.  As
	/// a consequence, the ciphertext is identical to the plaintext.  All
	/// initialization methods do nothing, while the blocksize is set to 1
	/// byte.
	/// 
	/// @since JCE1.2
	/// </summary>
	public class NullCipher : Cipher
	{
		public class NullCipherSpi : CipherSpi
		{
			/// <summary>
			/// Sets the mode of this cipher - no op.
			/// </summary>
			public override void engineSetMode(string mode)
			{
			}

			/// <summary>
			/// Sets the padding mechanism of this cipher - no op.
			/// </summary>
			public override void engineSetPadding(string padding)
			{
			}

			/// <summary>
			/// Returns the block size (in bytes) - 1
			/// </summary>
			public override int engineGetBlockSize()
			{
				return 1;
			}

			/// <summary>
			/// Returns the length in bytes that an output buffer would
			/// need to be in order to hold the result of the next <code>update</code>
			/// or <code>doFinal</code> operation, given the input length
			/// <code>inputLen</code> (in bytes).
			/// </summary>
			/// <param name="inputLen"> the input length (in bytes) </param>
			/// <returns> the required output buffer size (in bytes) </returns>
			public override int engineGetOutputSize(int inputLen)
			{
				return inputLen;
			}

			/// <summary>
			/// Returns the initialization vector (IV) in a new buffer. 
			/// </summary>
			/// <returns> null </returns>
			public override byte[] engineGetIV()
			{
				return null;
			}

			/// <summary>
			/// Returns the parameters used with this cipher - null
			/// </summary>
			public override AlgorithmParameters engineGetParameters()
			{
				return null;
			}

			/// <summary>
			/// Initializes this cipher with a key and a source
			/// of randomness - no op.
			/// </summary>
			public override void engineInit(int opmode, Key key, SecureRandom random)
			{
			}

			/// <summary>
			/// Initializes this cipher with a key, a set of
			/// algorithm parameters, and a source of randomness - no op.
			/// </summary>
			public override void engineInit(int opmode, Key key, AlgorithmParameterSpec @params, SecureRandom random)
			{
			}

			/// <summary>
			/// Initializes this cipher with a key, a set of
			/// algorithm parameters, and a source of randomness - no op.
			/// </summary>
			public override void engineInit(int opmode, Key key, AlgorithmParameters @params, SecureRandom random)
			{
			}

			/// <summary>
			/// Continues a multiple-part encryption or decryption operation
			/// (depending on how this cipher was initialized), processing another data
			/// part - in this case just return a copy of the input.
			/// </summary>
			public override byte[] engineUpdate(byte[] input, int inputOffset, int inputLen)
			{
				if (input == null)
				{
					return null;
				}

				byte[] tmp = new byte[inputLen];

				JavaSystem.arraycopy(input, inputOffset, tmp, 0, inputLen);

				return tmp;
			}

			/// <summary>
			/// Continues a multiple-part encryption or decryption operation
			/// (depending on how this cipher was initialized), processing another data
			/// part - in this case just copy the input to the output.
			/// </summary>
			public override int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
			{
				if (input == null)
				{
					return 0;
				}

				if ((output.Length - outputOffset) < inputLen)
				{
					throw new ShortBufferException("output buffer to short for NullCipher");
				}

				JavaSystem.arraycopy(input, inputOffset, output, outputOffset, inputLen);

				return inputLen;
			}

			/// <summary>
			/// Encrypts or decrypts data in a single-part operation, or finishes a multiple-part operation.
			/// The data is encrypted or decrypted, depending on how this cipher was initialized
			/// - in this case just return a copy of the input.
			/// </summary>
			public override byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
			{
				if (input == null)
				{
					return new byte[0];
				}

				byte[] tmp = new byte[inputLen];

				JavaSystem.arraycopy(input, inputOffset, tmp, 0, inputLen);

				return tmp;
			}

			/// <summary>
			/// Encrypts or decrypts data in a single-part operation,
			/// or finishes a multiple-part operation.
			/// The data is encrypted or decrypted, depending on how this cipher was
			/// initialized.
			/// </summary>
			public override int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
			{
				if (input == null)
				{
					return 0;
				}

				if ((output.Length - outputOffset) < inputLen)
				{
					throw new ShortBufferException("output buffer too short for NullCipher");
				}

				JavaSystem.arraycopy(input, inputOffset, output, outputOffset, inputLen);

				return inputLen;
			}

			/// <summary>
			/// Returns the key size of the given key object - 0
			/// </summary>
			public override int engineGetKeySize(Key key)
			{
				return 0;
			}
		}

		public NullCipher() : base(new NullCipherSpi(), null, "NULL")
		{
		}
	}

}