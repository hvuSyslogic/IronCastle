namespace org.bouncycastle.jcajce.spec
{

	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// Key spec for use with the scrypt SecretKeyFactory.
	/// </summary>
	public class ScryptKeySpec : KeySpec
	{
		private readonly char[] password;
		private readonly byte[] salt;
		private readonly int costParameter;
		private readonly int blockSize;
		private readonly int parallelizationParameter;
		private readonly int keySize;

		public ScryptKeySpec(char[] password, byte[] salt, int costParameter, int blockSize, int parallelizationParameter, int keySize)
		{

			this.password = password;
			this.salt = Arrays.clone(salt);
			this.costParameter = costParameter;
			this.blockSize = blockSize;
			this.parallelizationParameter = parallelizationParameter;
			this.keySize = keySize;
		}

		public virtual char[] getPassword()
		{
			return password;
		}

		public virtual byte[] getSalt()
		{
			return Arrays.clone(salt);
		}

		public virtual int getCostParameter()
		{
			return costParameter;
		}

		public virtual int getBlockSize()
		{
			return blockSize;
		}

		public virtual int getParallelizationParameter()
		{
			return parallelizationParameter;
		}

		/// <summary>
		/// Key length (in bits).
		/// </summary>
		/// <returns> length of the key to generate in bits. </returns>
		public virtual int getKeyLength()
		{
			return keySize;
		}
	}
}