namespace org.bouncycastle.openpgp
{
	public class PGPKdfParameters : PGPAlgorithmParameters
	{
		private readonly int hashAlgorithm;
		private readonly int symmetricWrapAlgorithm;

		public PGPKdfParameters(int hashAlgorithm, int symmetricWrapAlgorithm)
		{
			this.hashAlgorithm = hashAlgorithm;
			this.symmetricWrapAlgorithm = symmetricWrapAlgorithm;
		}

		public virtual int getSymmetricWrapAlgorithm()
		{
			return symmetricWrapAlgorithm;
		}

		public virtual int getHashAlgorithm()
		{
			return hashAlgorithm;
		}
	}

}