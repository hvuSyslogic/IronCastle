namespace javax.crypto.spec
{

	/// <summary>
	/// This class specifies the set of parameters used with password-based encryption (PBE), as defined in the
	/// <a href="http://www.rsa.com/rsalabs/pubs/PKCS/html/pkcs-5.html">PKCS #5</a> standard.
	/// </summary>
	public class PBEParameterSpec : AlgorithmParameterSpec
	{
		private byte[] salt;
		private int iterationCount;

		/// <summary>
		/// Constructs a parameter set for password-based encryption as defined in
		/// the PKCS #5 standard.
		/// </summary>
		/// <param name="salt"> the salt. </param>
		/// <param name="iterationCount"> the iteration count. </param>
		public PBEParameterSpec(byte[] salt, int iterationCount)
		{
			this.salt = new byte[salt.Length];
			JavaSystem.arraycopy(salt, 0, this.salt, 0, salt.Length);

			this.iterationCount = iterationCount;
		}

		/// <summary>
		/// Returns the salt.
		/// </summary>
		/// <returns> the salt </returns>
		public virtual byte[] getSalt()
		{
			byte[] tmp = new byte[salt.Length];

			JavaSystem.arraycopy(salt, 0, tmp, 0, salt.Length);

			return tmp;
		}

		/// <summary>
		/// Returns the iteration count.
		/// </summary>
		/// <returns> the iteration count </returns>
		public virtual int getIterationCount()
		{
			return iterationCount;
		}
	}

}