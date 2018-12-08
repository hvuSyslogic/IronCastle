using BouncyCastle.Core.Port;

namespace org.bouncycastle.pqc.crypto.xmss
{

	using KeyGenerationParameters = org.bouncycastle.crypto.KeyGenerationParameters;

	/// <summary>
	/// XMSS key-pair generation parameters.
	/// </summary>
	public sealed class XMSSKeyGenerationParameters : KeyGenerationParameters
	{
		private readonly XMSSParameters xmssParameters;

		/// <summary>
		/// XMSSMT constructor...
		/// </summary>
		/// <param name="prng">   Secure random to use. </param>
		public XMSSKeyGenerationParameters(XMSSParameters xmssParameters, SecureRandom prng) : base(prng,-1)
		{

			this.xmssParameters = xmssParameters;
		}

		public XMSSParameters getParameters()
		{
			return xmssParameters;
		}
	}

}