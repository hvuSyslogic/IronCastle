namespace org.bouncycastle.cert.crmf.bc
{

	using Digest = org.bouncycastle.crypto.Digest;
	using SHA1Digest = org.bouncycastle.crypto.digests.SHA1Digest;
	using MGF1BytesGenerator = org.bouncycastle.crypto.generators.MGF1BytesGenerator;
	using MGFParameters = org.bouncycastle.crypto.@params.MGFParameters;

	/// <summary>
	/// An encrypted value padder that uses MGF1 as the basis of the padding.
	/// </summary>
	public class BcFixedLengthMGF1Padder : EncryptedValuePadder
	{
		private int length;
		private SecureRandom random;
		private Digest dig = new SHA1Digest();

		/// <summary>
		/// Create a padder to so that padded output will always be at least
		/// length bytes long.
		/// </summary>
		/// <param name="length"> fixed length for padded output. </param>
		public BcFixedLengthMGF1Padder(int length) : this(length, null)
		{
		}

		/// <summary>
		/// Create a padder to so that padded output will always be at least
		/// length bytes long, using the passed in source of randomness to
		/// provide the random material for the padder.
		/// </summary>
		/// <param name="length"> fixed length for padded output. </param>
		/// <param name="random"> a source of randomness. </param>
		public BcFixedLengthMGF1Padder(int length, SecureRandom random)
		{
			this.length = length;
			this.random = random;
		}

		public virtual byte[] getPaddedData(byte[] data)
		{
			byte[] bytes = new byte[length];
			byte[] seed = new byte[dig.getDigestSize()];
			byte[] mask = new byte[length - dig.getDigestSize()];

			if (random == null)
			{
				random = new SecureRandom();
			}

			random.nextBytes(seed);

			MGF1BytesGenerator maskGen = new MGF1BytesGenerator(dig);

			maskGen.init(new MGFParameters(seed));

			maskGen.generateBytes(mask, 0, mask.Length);

			JavaSystem.arraycopy(seed, 0, bytes, 0, seed.Length);
			JavaSystem.arraycopy(data, 0, bytes, seed.Length, data.Length);

			for (int i = seed.Length + data.Length + 1; i != bytes.Length; i++)
			{
				bytes[i] = (byte)(1 + random.nextInt(255));
			}

			for (int i = 0; i != mask.Length; i++)
			{
				bytes[i + seed.Length] ^= mask[i];
			}

			return bytes;
		}

		public virtual byte[] getUnpaddedData(byte[] paddedData)
		{
			byte[] seed = new byte[dig.getDigestSize()];
			byte[] mask = new byte[length - dig.getDigestSize()];

			JavaSystem.arraycopy(paddedData, 0, seed, 0, seed.Length);

			MGF1BytesGenerator maskGen = new MGF1BytesGenerator(dig);

			maskGen.init(new MGFParameters(seed));

			maskGen.generateBytes(mask, 0, mask.Length);

			for (int i = 0; i != mask.Length; i++)
			{
				paddedData[i + seed.Length] ^= mask[i];
			}

			int end = 0;

			for (int i = paddedData.Length - 1; i != seed.Length; i--)
			{
				if (paddedData[i] == 0)
				{
					end = i;
					break;
				}
			}

			if (end == 0)
			{
				throw new IllegalStateException("bad padding in encoding");
			}

			byte[] data = new byte[end - seed.Length];

			JavaSystem.arraycopy(paddedData, seed.Length, data, 0, data.Length);

			return data;
		}
	}

}