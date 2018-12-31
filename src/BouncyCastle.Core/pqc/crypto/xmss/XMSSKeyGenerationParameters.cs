using BouncyCastle.Core.Port;
using org.bouncycastle.crypto;

namespace org.bouncycastle.pqc.crypto.xmss
{

	
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