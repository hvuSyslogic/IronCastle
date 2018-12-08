using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.@params
{
	using ECPoint = org.bouncycastle.math.ec.ECPoint;

	/// <summary>
	/// Private parameters for an SM2 key exchange. The ephemeralPrivateKey is used to calculate the random point used in the algorithm.
	/// </summary>
	public class SM2KeyExchangePrivateParameters : CipherParameters
	{
		private readonly bool initiator;
		private readonly ECPrivateKeyParameters staticPrivateKey;
		private readonly ECPoint staticPublicPoint;
		private readonly ECPrivateKeyParameters ephemeralPrivateKey;
		private readonly ECPoint ephemeralPublicPoint;

		public SM2KeyExchangePrivateParameters(bool initiator, ECPrivateKeyParameters staticPrivateKey, ECPrivateKeyParameters ephemeralPrivateKey)
		{
			if (staticPrivateKey == null)
			{
				throw new NullPointerException("staticPrivateKey cannot be null");
			}
			if (ephemeralPrivateKey == null)
			{
				throw new NullPointerException("ephemeralPrivateKey cannot be null");
			}

			ECDomainParameters parameters = staticPrivateKey.getParameters();
			if (!parameters.Equals(ephemeralPrivateKey.getParameters()))
			{
				throw new IllegalArgumentException("Static and ephemeral private keys have different domain parameters");
			}

			this.initiator = initiator;
			this.staticPrivateKey = staticPrivateKey;
			this.staticPublicPoint = parameters.getG().multiply(staticPrivateKey.getD()).normalize();
			this.ephemeralPrivateKey = ephemeralPrivateKey;
			this.ephemeralPublicPoint = parameters.getG().multiply(ephemeralPrivateKey.getD()).normalize();
		}

		public virtual bool isInitiator()
		{
			return initiator;
		}
		public virtual ECPrivateKeyParameters getStaticPrivateKey()
		{
			return staticPrivateKey;
		}

		public virtual ECPoint getStaticPublicPoint()
		{
			return staticPublicPoint;
		}

		public virtual ECPrivateKeyParameters getEphemeralPrivateKey()
		{
			return ephemeralPrivateKey;
		}

		public virtual ECPoint getEphemeralPublicPoint()
		{
			return ephemeralPublicPoint;
		}
	}

}