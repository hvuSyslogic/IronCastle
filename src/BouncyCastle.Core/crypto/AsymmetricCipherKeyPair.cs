using org.bouncycastle.crypto.@params;

namespace org.bouncycastle.crypto
{
	
	/// <summary>
	/// a holding class for public/private parameter pairs.
	/// </summary>
	public class AsymmetricCipherKeyPair
	{
		private AsymmetricKeyParameter publicParam;
		private AsymmetricKeyParameter privateParam;

		/// <summary>
		/// basic constructor.
		/// </summary>
		/// <param name="publicParam"> a public key parameters object. </param>
		/// <param name="privateParam"> the corresponding private key parameters. </param>
		public AsymmetricCipherKeyPair(AsymmetricKeyParameter publicParam, AsymmetricKeyParameter privateParam)
		{
			this.publicParam = publicParam;
			this.privateParam = privateParam;
		}

		/// <summary>
		/// basic constructor.
		/// </summary>
		/// <param name="publicParam"> a public key parameters object. </param>
		/// <param name="privateParam"> the corresponding private key parameters. </param>
		/// @deprecated use AsymmetricKeyParameter 
		public AsymmetricCipherKeyPair(CipherParameters publicParam, CipherParameters privateParam)
		{
			this.publicParam = (AsymmetricKeyParameter)publicParam;
			this.privateParam = (AsymmetricKeyParameter)privateParam;
		}

		/// <summary>
		/// return the public key parameters.
		/// </summary>
		/// <returns> the public key parameters. </returns>
		public virtual AsymmetricKeyParameter getPublic()
		{
			return publicParam;
		}

		/// <summary>
		/// return the private key parameters.
		/// </summary>
		/// <returns> the private key parameters. </returns>
		public virtual AsymmetricKeyParameter getPrivate()
		{
			return privateParam;
		}
	}

}