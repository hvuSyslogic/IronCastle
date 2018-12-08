using BouncyCastle.Core.Port;

namespace org.bouncycastle.pqc.crypto.xmss
{

	using KeyGenerationParameters = org.bouncycastle.crypto.KeyGenerationParameters;

	/// <summary>
	/// XMSS^MT key-pair generation parameters.
	/// </summary>
	public sealed class XMSSMTKeyGenerationParameters : KeyGenerationParameters
	{
		private readonly XMSSMTParameters xmssmtParameters;

		/// <summary>
		/// XMSSMT constructor...
		/// </summary>
		/// <param name="prng">   Secure random to use. </param>
		public XMSSMTKeyGenerationParameters(XMSSMTParameters xmssmtParameters, SecureRandom prng) : base(prng,-1)
		{

			this.xmssmtParameters = xmssmtParameters;
		}

		public XMSSMTParameters getParameters()
		{
			return xmssmtParameters;
		}
	}

}