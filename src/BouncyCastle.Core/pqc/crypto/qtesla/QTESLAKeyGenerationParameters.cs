using BouncyCastle.Core.Port;

namespace org.bouncycastle.pqc.crypto.qtesla
{

	using KeyGenerationParameters = org.bouncycastle.crypto.KeyGenerationParameters;

	/// <summary>
	/// qTESLA key-pair generation parameters.
	/// </summary>
	public class QTESLAKeyGenerationParameters : KeyGenerationParameters
	{
		private readonly int securityCategory;

		/// <summary>
		/// Base constructor - provide the qTESLA security category and a source of randomness.
		/// </summary>
		/// <param name="securityCategory"> the security category to generate the parameters for. </param>
		/// <param name="random">           the random byte source. </param>
		public QTESLAKeyGenerationParameters(int securityCategory, SecureRandom random) : base(random, -1)
		{

			QTESLASecurityCategory.getPrivateSize(securityCategory); // check the category is valid

			this.securityCategory = securityCategory;
		}

		/// <summary>
		/// Return the security category for these parameters.
		/// </summary>
		/// <returns> the security category for keys generated using these parameters. </returns>
		public virtual int getSecurityCategory()
		{
			return securityCategory;
		}
	}

}